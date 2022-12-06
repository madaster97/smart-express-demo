const helmet = require('helmet');
const express = require('express')
const { v4 } = require('uuid');
const got = require('got').default;
const jose = require('jose');
const app = express()
const { auth, requiresAuth } = require('express-openid-connect');
const createHttpError = require('http-errors');
const MemoryStore = require('memorystore')(auth);

const debug = require('debug')('fhiruser');

// ENV setup
const port = 3000
const isProd = process.env.NODE_ENV == 'production';
const fhirIss = process.env.FHIR_ISS;
if (!fhirIss) {
  throw new Error('Missing FHIR_ISS environment variable')
}
const launchUrl = process.env.BASE_URL + "/launch";
const clientId = process.env.CLIENT_ID
const maxTabCount = process.env.MAX_TAB_COUNT || 4;
const framer = process.env.FRAMER_ORIGIN;
const allowFraming = !!framer;
if (!allowFraming) {
  debug(`FRAMER_ORIGIN environment variable is empty.
    App will reject iframing by using Lax cookies, and by setting CSP or X-Frame-Options to block framing. 
    Provide an allowed origin "https://first.ehr1.com/" to allow framing from that site`)
} else {
  // TODO: Validate provided framers
  debug('iframing allowed from %s', framer);
}

// Header protection setup
if (!allowFraming) {
  // Default, disallows framing
  app.use(helmet({}))
} else {
  const isIEReq = (req) => req.headers['user-agent'].includes('Trident');
  app.use(
    helmet({
      frameguard: false,
      contentSecurityPolicy: {
        directives: {
          ...helmet.contentSecurityPolicy.getDefaultDirectives(),
          "frame-ancestors": [framer]
        }
      }
    }),
    (req, res, next) => {
      // Populate X-Frame for IE requests
      if (isIEReq(req)) {
        res.setHeader('X-Frame-Options', 'ALLOW-FROM ' + framer)
      } else {
        // Omit X-Frame-Options intentionally
        // There is no X-Frame directive that allows framing in modern browsers. Use CSP instead
      }
      next('route')
    })
}

app.set('view engine', 'pug');

/*
"express-openid-connect" SDK handles:
1. Session management using HTTP cookies
2. Client authentication
3. Creating a `redirect_uri` at /callback wherever it is mounted
4. Redirecting to a /tab/:tabId endpoint. 
  - Special handling I wrote to inject patient/encounter context into cookie
  - See getLoginState and afterCallback below
*/
app.use(
  auth({
    authorizationParams: {
      response_type: 'code' // Required, otherwise SDK skips client_secret even on res.oidc.login
    },
    authRequired: false,
    errorOnRequiredAuth: true,
    session: {
      store: new MemoryStore({
        // 5 minutes, just for this test app
        checkPeriod: 5 * 60 * 1000,
      }),
      cookie: {
        // Embedding in an iframe requires SameSite=None, counts as third party cookie
        // Otherwise set to Strict. Can be downgraded to Lax if preferred
        sameSite: allowFraming ? "None" : "Strict"
      }
    },
    transactionCookie: {
      // Explicitly setting pre-login cookie as well
      // Lax is required for redirects to include transaction cookie
      sameSite: allowFraming ? "None" : "Lax"
    },
    routes: {
      // Set to false to turn off standalone launch (/login endpoint)
      // I think there are risks to standalone + EHR on the same router
      // Especially risky when allowing third party cookies
      login: false
    },
    getLoginState: () => {
      // New UUID to represent this login
      const tabId = v4();
      return {
        // TODO: Centralize logic for grabbing tabId + defining route
        returnTo: `/tab/${tabId}`,
        tabId
      }
    },
    afterCallback: async (req, res, session, state) => {
      // tokenSet.patient is what I'm after
      // See https://hl7.org/fhir/smart-app-launch/1.0.0/scopes-and-launch-context/index.html#launch-context-arrives-with-your-access_token
      if (!session.patient) {
        return Promise.reject('Patient missing from context. Does your auth server support launch/patient scope?');
      } else {
        const { access_token, id_token, token_type, expires_at, refresh_token, ...context } = session;
        const tabData = {
          ...context,
          access_token,
          token_type,
          expires_at,
          // TODO: Remove refresh_token or use it below
          refresh_token
        }
        const idTokenClaims = jose.JWT.decode(session.id_token);
        const isSameUser =
          req.oidc.isAuthenticated()
          && req.oidc.user.sub == idTokenClaims.sub;
        /* Example tabs array:
        [
          {
            tabId: "5636ab83-167b-405e-af9f-1fbdbaf1aefc"
            data: {
              "access_token": "<omitted>",
              "scope": "<omitted>",
              "encounter": "eNe8sUNfKPazxTIA2rGmlbg3",
              "need_patient_banner": "false",
              "patient": "eTjDDWfopD0BnRlyEO2mGZQ3",
              ...
            }
          },
          {
            tabId: "1daba7a1-0960-4e62-9014-1626a20f33dc",
            data: {
              "access_token": "<omitted>",
              "scope": "<omitted>",
              "encounter": "eajyq3tHTNbfPFZexvvMthA3",
              "need_patient_banner": "false",
              "patient": "eXFljJT8WxVd2PjwvPAGR1A3",
              ...
            }
          }
        ]
        */
        const newTabObject = {
          tabId: state.tabId,
          data: tabData
        }
        if (!isSameUser) {
          debug('Warning. New user logged in to existing session. Clearing existing session');
          return Promise.resolve({
            id_token,
            tabs: [newTabObject]
          })
        } else {
          const existingTabs = req.appSession.tabs;
          const tabCount = existingTabs.length;
          if (tabCount > maxTabCount) {
            debug(`Server Error. Max tab count (${maxTabCount}) exceeded by sesion with ${tabCount} tabs. Clearing existing session`)
            return Promise.resolve({
              id_token,
              tabs: [newTabObject]
            })
          } else if (tabCount == maxTabCount) {
            // Remove first tab, without modifying existingTabs
            const [_removing, ...filteredTabs] = existingTabs;
            return Promise.resolve({
              id_token,
              tabs: [
                ...filteredTabs,
                newTabObject
              ]
            })
          } else {
            // Add new tab to the end of array
            return Promise.resolve({
              id_token,
              tabs: [
                ...existingTabs,
                newTabObject
              ]
            })
          }
        };
      }
    }
  })
);

// Resource server initiating an authorize request
// Per SMART App Launch: https://hl7.org/fhir/smart-app-launch/1.0.0/#ehr-launch-sequence
app.get('/launch', (req, res, next) => {
  const req_iss = req.query.iss;
  if (!req_iss) {
    next(createHttpError(400, "'iss' parameter missing. Should be " + fhirIss))
  } else if (req_iss != fhirIss) {
    next(createHttpError(400, `iss mismatch. Expected ${fhirIss} and received ${req_iss}`))
  } else if (!req.query.launch) {
    next(createHttpError(400, "Missing 'launch' param"))
  } else {
    res.oidc.login({
      authorizationParams: {
        response_type: 'code',
        aud: fhirIss,
        scope: 'launch openid fhirUser launch/patient',
        launch: req.query.launch
      }
    })
  }
})

app.post('/tab/:tabId/csrf-test', (req, res, next) => {
  if (!req.oidc.isAuthenticated()) {
    res.send('CSRF successfuly blocked!')
  } else {
    res.send('Oh no. The CSRF went through...')
  }
})

app.get('/tab/:tabId/logout', requiresAuth(), async (req, res, next) => {
  const requestedTab = req.params.tabId;
  const tabDataIndex = req.appSession.tabs.findIndex(tab => tab.tabId == requestedTab);
  if (tabDataIndex == -1) {
    next(createHttpError(403, 'Requested tab forbidden'))
  } else {
      req.appSession.tabs.splice(tabDataIndex, 1);
    res.send('Logged out of this tab. Please close')
  }
})

app.get('/tab/:tabId', requiresAuth(), async (req, res, next) => {
  const requestedTab = req.params.tabId;
  const tabDataIndex = req.appSession.tabs.findIndex(tab => tab.tabId == requestedTab);
  if (tabDataIndex == -1) {
    next(createHttpError(403, 'Requested tab forbidden'))
  } else {
    // Request patient data!
    const tabData = req.appSession.tabs[tabDataIndex].data;
    const Authorization = tabData.token_type + ' ' + tabData.access_token;
    const patient = await got(fhirIss + '/Patient/' + tabData.patient, {
      headers: {
        Authorization
      }
    }).json();
    // TODO, error handling around name parsing
    const nameObject = patient.name[0];
    const name = nameObject.family + ", " + nameObject.given[0];
    res.render('tab', {
      title: "Seeing " + name,
      message: "Seeing Patient " + name,
      patient: JSON.stringify(patient, null, 2),
      tabId: requestedTab
    })
  }
})

app.get('/', (req, res) => {
  if (!req.oidc.isAuthenticated()) {
    res.render('login', {
      title: "Log into fhiruser",
      message: "Launch this app from the EHR to login",
      fhirIss: fhirIss,
      launchUrl: launchUrl,
      clientId: clientId
    })
  } else {
    res.render('index', {
      title: "Welcome to fhiruser",
      message: "Logged in with these tabs",
      tabs: req.appSession.tabs
    })
  }
});

if (!isProd) {
  app.get('/debug', requiresAuth(), (req, res) => {
    res.json({
      user: req.oidc.user,
      appSession: req.appSession
    })
  });
}

// error handlers
app.use(function (err, req, res, next) {
  res.status(err.status || 500);

  switch (err.status) {
    case 404:
      break;
    default:
      debug('Error handled: %o', err);
      break;
  }

  res.render('error', {
    message: err.message,
    error: !isProd ? err : {}
  });
});

app.listen(port, () => {
  debug(`Launch to ${launchUrl}. Only iss ${fhirIss} will be accepted`)
});