const express = require('express')
const { v4 } = require('uuid');
const got = require('got').default;
const { JWT: { decode: jwtDecode } } = require('jose');
const app = express()
const { auth, requiresAuth } = require('express-openid-connect');
const createHttpError = require('http-errors');

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
    session: {
      cookie: {
        // Embedding in EHR iframe requires SameSite=None, counts as third party cookie
        // TODO: Implement iframe protection on app using HTTP response headers
        sameSite: "None"
      }
    },
    transactionCookie: {
      // Explicitly setting pre-login cookie as well
      sameSite: "None"
    },
    routes: {
      // Set to false to turn off standalone launch (/login endpoint)
      // If you use standalone, set sameSite to "Strict" for session and "Lax" for transaction cookie
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
        const { access_token, id_token, token_type, expires_at, refresh_token, ...tabData } = session;
        const idTokenClaims = jwtDecode(session.id_token);
        const isSameUser =
          req.oidc.isAuthenticated()
          && req.oidc.user.sub == idTokenClaims.sub;
        /* Example tabs object. Keys are tabIds
        {
          "5636ab83-167b-405e-af9f-1fbdbaf1aefc": {
            "scope": "<omitted>",
            "encounter": "eNe8sUNfKPazxTIA2rGmlbg3",
            "need_patient_banner": "false",
            "patient": "eTjDDWfopD0BnRlyEO2mGZQ3",
            ...
          },
          "1daba7a1-0960-4e62-9014-1626a20f33dc": {
            "scope": "<omitted>",
            "encounter": "eajyq3tHTNbfPFZexvvMthA3",
            "need_patient_banner": "false",
            "patient": "eXFljJT8WxVd2PjwvPAGR1A3",
            ...
          }
        }
        */
        const tabs = isSameUser
          // Same user logged in, combine tabs
          ? {
            [state.tabId]: tabData,
            // REVIEW please. Grab old appSession to add to new session
            ...req.appSession.tabs
          }
          // New user logged in, create new tabs object
          : {
            [state.tabId]: tabData
          };
        return Promise.resolve({
          access_token,
          id_token,
          token_type,
          expires_at,
          refresh_token,
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
        scope: 'launch openid fhirUser launch/patient',
        launch: req.query.launch
      }
    })
  }
})

app.get('/tab/:tabId', requiresAuth(), async (req, res) => {
  const requestedTab = req.params.tabId;
  const tabData = req.appSession.tabs[requestedTab];
  if (!tabData) {
    next(createHttpError(403, 'Requested tab forbidden'))
  } else {
    // Request patient data!
    const tokenSet = req.oidc.accessToken;
    const patient = await got(fhirIss + '/Patient/' + tabData.patient, {
      headers: {
        Authorization: tokenSet.token_type + ' ' + tokenSet.access_token
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