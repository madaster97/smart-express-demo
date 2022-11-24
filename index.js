const express = require('express')
const { v4 } = require('uuid');
const got = require('got').default;
const { JWT: {decode: jwtDecode} } = require('jose');
const app = express()
const port = 3000
const debug = require('debug')('fhirUser');

const FHIR_ISS = process.env.FHIR_ISS;
if (!FHIR_ISS) {
  throw new Error('Missing FHIR_ISS environment variable')
}

const { auth, requiresAuth } = require('express-openid-connect');
app.use(
  auth({
    authorizationParams: {
      response_type: 'code',
      aud: FHIR_ISS,
      scope: 'launch openid fhirUser launch/patient'
    },
    authRequired: false,
    session: {
      cookie: {
        // Embedding in EHR iframe requires None, counts as cross-site
        // TODO: Implement iframe protection using HTTP response headers
        sameSite: "None"
      }
    },
    getLoginState: () => {
      // New UUID to represent this login
      const tabId = v4();
      return {
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
        const id_token = jwtDecode(session.id_token);
        if (!id_token.fhirUser) {
          return Promise.reject('"fhirUser" claim missing');
        } else {
          const tabs = req.oidc.isAuthenticated()
            && req.oidc.user.sub == id_token.sub
            // Same user logged in, combine tabs
            ? {
              [state.tabId]: { patient: session.patient },
              ...req.appSession.tabs
            }
            // New user logged in, create new tabs
            : {
              [state.tabId]: { patient: session.patient }
            };
          return Promise.resolve({
            ...session,
            tabs
          });
        }
      }
    }
  })
);

app.get('/launch', (req, res) => {
  const req_iss = req.query.iss;
  if (req_iss != FHIR_ISS) {
    res.send(`iss mismatch. Expected ${FHIR_ISS} and received ${req_iss}`)
  } else if (!req.query.launch) {
    res.send('Missing launch param')
  } else {
    res.oidc.login({
      authorizationParams: {
        response_type: 'code',
        aud: FHIR_ISS,
        scope: 'launch openid fhirUser launch/patient',
        launch: req.query.launch
      }
    })
  }
})

app.get('/tab/:tabId/patient', requiresAuth(), async (req, res) => {
  const requestedTab = req.params.tabId;
  const tabData = req.appSession.tabs[requestedTab];
  if (!tabData) {
    res.send('Requested tab forbidden') //403
  } else {
    // Request patient data!
    const tokenSet = req.oidc.accessToken;
    const patient = await got(FHIR_ISS + '/Patient/' + tabData.patient, {
      headers: {
        Authorization: tokenSet.token_type + ' ' + tokenSet.access_token
      }
    }).json();
    res.json(patient);
  }
})

app.get('/tab/:tabId', requiresAuth(), async (req, res) => {
  const requestedTab = req.params.tabId;
  const tabData = req.appSession.tabs[requestedTab];
  if (!tabData) {
    res.send('Requested tab forbidden') //403
  } else {
    res.send('Logged in as ' + req.oidc.user.fhirUser + ' with patient ' + tabData.patient
      + `, try browsing to ${process.env.BASE_URL}/tab/${requestedTab}/patient`) //400
  }
})

app.get('/appSession', (req, res) => {
  if (!req.oidc.isAuthenticated()) {
    res.send('Not Logged In')
  } else {
    res.json(req.appSession);
  }
});

app.get('/', (req, res) => {
  if (!req.oidc.isAuthenticated()) {
    res.send('Not Logged In')
  } else {
    res.send('Logged in as ' + req.oidc.user.fhirUser + ', with these tabs: ' + JSON.stringify(req.appSession.tabs, null, 2));
  }
});

app.listen(port, () => {
  debug(`Launch to ${process.env.BASE_URL}/launch. Only iss ${FHIR_ISS} will be accepted`)
});