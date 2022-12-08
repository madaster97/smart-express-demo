const helmet = require('helmet');
const express = require('express')
const { v4 } = require('uuid');
const got = require('got').default;
const jose = require('jose');
const app = express()
const { auth, requiresAuth } = require('express-openid-connect');
const createHttpError = require('http-errors');
const MemoryStore = require('memorystore')(auth);
const crypto = require('crypto');

const debug = require('debug')('fhiruser');

// ENV setup
const port = 3000
const isProd = process.env.NODE_ENV == 'production';
const fhirIss = process.env.FHIR_ISS;
if (!fhirIss) {
  throw new Error('Missing FHIR_ISS environment variable')
}
const launchUrl = process.env.BASE_URL + "/launch";
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
        // Otherwise set to Lax. Can be upgraded to Strict if preferred
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
        const genToken = () => crypto.randomBytes(32).toString('hex');
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
          const csrfToken = genToken();
          debug('Warning. New user logged in to existing session. Clearing existing session');
          return Promise.resolve({
            id_token,
            csrfToken,
            tabs: [newTabObject]
          })
        } else {
          const existingTabs = req.appSession.tabs;
          const existingCsrfToken = req.appSession.csrfToken;
          const tabCount = existingTabs.length;
          if (tabCount > maxTabCount) {
            debug(`Server Error. Max tab count (${maxTabCount}) exceeded by sesion with ${tabCount} tabs. Clearing existing tabs`)
            return Promise.resolve({
              id_token,
              csrfToken: existingCsrfToken,
              tabs: [newTabObject]
            })
          } else if (tabCount == maxTabCount) {
            // Remove first tab, without modifying existingTabs
            const [_removing, ...filteredTabs] = existingTabs;
            return Promise.resolve({
              id_token,
              csrfToken: existingCsrfToken,
              tabs: [
                ...filteredTabs,
                newTabObject
              ]
            })
          } else {
            // Add new tab to the end of array
            return Promise.resolve({
              id_token,
              csrfToken: existingCsrfToken,
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

const getPatient = async (tabData) => {
  const tabData = req.appSession.tabs[tabDataIndex].data;
    const Authorization = tabData.token_type + ' ' + tabData.access_token;
    return got(fhirIss + '/Patient/' + tabData.patient, {
      headers: {
        Authorization
      }
    }).json();
}

const getPatientName = (patient) => {
  // TODO, error handling around name parsing
  const nameObject = patient.name[0];
  return nameObject.family + ", " + nameObject.given[0];
}

app.post('/tab/:tabId/patient-admit', requiresAuth(), express.urlencoded({ extended: false }), async (req, res, next) => {
  const inputToken = req.body['CSRFToken'];
  const expectedToken = req.appSession.csrfToken;
  const badRequest = (msg) => next(createHttpError(400, msg));
  if (!inputToken) {
    badRequest('Error, CSRF token missing');
  } else if (Array.isArray(inputToken)) {
    badRequest('Error, too many CSRF tokens');
  } else if (inputToken != expectedToken) {
    badRequest('Error, invalid CSRF token');
  } else {
    const requestedTab = req.params.tabId;
    const tabDataIndex = req.appSession.tabs.findIndex(tab => tab.tabId == requestedTab);
    if (tabDataIndex == -1) {
      next(createHttpError(403, 'Requested tab forbidden'))
    } else {
      const tabData = req.appSession.tabs[tabDataIndex].data;
      req.appSession.tabs.splice(tabDataIndex, 1); //Logout of tab
      const patient = await getPatient(tabData);
      const name = getPatientName(patient);
      res.send('Succesfully admitted patient ' + name +'. Hopefully you meant to do that! Close this tab');
    }
  }
})

app.get('/tab/:tabId', requiresAuth(), async (req, res, next) => {
  const requestedTab = req.params.tabId;
  const tabDataIndex = req.appSession.tabs.findIndex(tab => tab.tabId == requestedTab);
  if (tabDataIndex == -1) {
    next(createHttpError(403, 'Requested tab forbidden'))
  } else {
    const patient = await getPatient(tabData);
    const name = getPatientName(patient);
    res.render('tab', {
      title: "Seeing " + name,
      message: "Seeing Patient " + name,
      patient: JSON.stringify(patient, null, 2),
      tabId: requestedTab,
      csrfToken: req.appSession.csrfToken
    })
  }
})

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