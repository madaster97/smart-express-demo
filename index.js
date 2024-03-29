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
const maxTabCount = process.env.MAX_TAB_COUNT || 4;
const framer = process.env.FRAMER_ORIGIN;
const allowFraming = !!framer;
if (!allowFraming) {
  debug(`FRAMER_ORIGIN environment variable is empty.
App will reject iframing by using Lax cookies, and by setting CSP or X-Frame-Options to block framing. 
Provide FRAMER_ORIGIN (example: https://*.ehr1.com/) to allow framing from that site`)
} else {
  // TODO: Validate provided framers
  debug('iframing allowed from %s', framer);
}

// Header protection setup
if (!allowFraming) {
  // Default, disallows framing
  app.use(helmet({}))
} else {
  // Require framing, and only from allowed origins
  // Framing is required because of iframe security concessions, like SameSite=None cookies
  // This library cannot selectively turn off those conecssions per request
  const isIEReq = (req) => req.headers['user-agent'].includes('Trident');
  const isIFrameReq = (req) => req.headers['sec-fetch-dest'] === 'iframe';
  app.use(
    (req, res, next) => {
      if (isIFrameReq(req)) {
        next('route')
      } else {
        next(createHttpError(403, "App must be iframed. 'sec-fetch-dest' indicated otherwise"))
      }
    },
    helmet({
      frameguard: false,
      contentSecurityPolicy: {
        directives: {
          ...helmet.contentSecurityPolicy.getDefaultDirectives(),
          // If framers needs to be a list, put multiple here!
          "frame-ancestors": [framer]
        }
      }
    }),
    (req, res, next) => {
      // Populate X-Frame-Options for IE requests
      if (isIEReq(req)) {
        // Does not accept multiple framers 
        // If you need multiple framers, check "Referer" or "Origin" req headers
        // If recognized, set that URL as the framer
        // https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#identifying-source-origin-via-originreferer-header
        res.setHeader('X-Frame-Options', 'ALLOW-FROM ' + framer)
      } else {
        // Omit X-Frame-Options intentionally
        // There is no directive that allows framing in modern browsers. Omit and use CSP instead
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
    authRequired: true,
    errorOnRequiredAuth: true,
    session: {
      store: new MemoryStore({
        // 5 minutes, just for this test app
        checkPeriod: 5 * 60 * 1000,
      }),
      cookie: {
        // Embedding in an iframe requires SameSite=None, counts as third party cookie
        // Otherwise set to lax so /callback can see existing appSession tabs
        sameSite: allowFraming ? "None" : "Lax"
      },
    },
    transactionCookie: {
      // Explicitly setting pre-login cookie as well
      // Lax is required for redirects to include transaction cookie
      sameSite: allowFraming ? "None" : "Lax"
    },
    routes: {
      // Set to false to turn off standalone launch (/login endpoint)
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
        // Setup this login's tabObject
        const { access_token, id_token, token_type, expires_at, refresh_token, ...context } = session;
        const tabData = {
          ...context,
          access_token,
          token_type,
          expires_at,
          refresh_token
        };
        const newTabObject = {
          tabId: state.tabId,
          data: tabData
        };

        // Handle new auth, re-auth or replacement auth
        const { sub: newSub } = jose.JWT.decode(session.id_token);
        let tabs;
        if (req.oidc.isAuthenticated()) {
          if (req.oidc.user.sub === newSub) {
            // If it's the same user logging in again
            // Add new tab to tail of tabs list
            const existingTabs = req.appSession.tabs;
            const tabCount = existingTabs.length;
            if (tabCount > maxTabCount) {
              debug(`Server Error. Max tab count (${maxTabCount}) exceeded by sesion with ${tabCount} tabs. Clearing existing tabs`);
              tabs = [newTabObject];
            } else if (tabCount == maxTabCount) {
              const [_removing, ...filteredTabs] = existingTabs;
              tabs = [...filteredTabs, newTabObject];
            } else { 
              tabs = [...existingTabs, newTabObject];
            }
          } else {
            // If it's a different user, replace the tabs
            tabs = [newTabObject];
            debug(`Warning. A new user authenticated over another user's session`)
          }
        } else {
          // If a new user is replacing an anonymous session, replace the tabs
          tabs = [newTabObject];
        }

        return Promise.resolve({
          // Intentionally remove access/refresh. Should be in the tabData
          id_token,
          tabs
        });
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
        scope: 'launch openid fhirUser',
        launch: req.query.launch
      }
    })
  }
})

const getPatient = async (tabData) => {
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
  return nameObject.family + ", " + nameObject.given.join(' ');
}

app.get('/tab/:tabId', async (req, res, next) => {
  const requestedTab = req.params.tabId;
  const tabDataIndex = req.appSession.tabs.findIndex(tab => tab.tabId == requestedTab);
  if (tabDataIndex == -1) {
    next(createHttpError(403, 'Requested tab forbidden'))
  } else {
    const tabData = req.appSession.tabs[tabDataIndex].data;
    const patient = await getPatient(tabData);
    const name = getPatientName(patient);
    res.render('tab', {
      title: "Seeing " + name,
      message: "Seeing Patient " + name,
      patient: JSON.stringify(patient, null, 2),
      tabId: requestedTab,
      tabData: JSON.stringify(tabData, null, 2)
    })
  }
})

if (!isProd) {
  app.get('/debug', (req, res) => {
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