# smart-express-demo
An example express app supporting SMART on FHIR. Supports multiple browser tabs protected by a shared cookie

# Running the App
Remember `npm install`, of course

In one terminal, run the server:
```
node -r dotenv/config . dotenv_config_path=config/smart-launch.env
```

In another terminal, run Caddy to to add TLS:
```
caddy reverse-proxy --from localhost -to localhost:3000
```

Open the [SMART App Launcher](https://launch.smarthealthit.org/?auth_error=&fhir_version_2=r4&iss=&launch_ehr=1&launch_url=https%3A%2F%2Flocalhost%2Flaunch&patient=&prov_skip_auth=1&provider=&pt_skip_auth=1&public_key=&sde=&sim_ehr=1&token_lifetime=15&user_pt=&launch=WzAsIjY3Y2JmMDkwLTRkZGItNDc5OS05OWZmLWEyOGFiZTI3NDBiMSw4N2EzMzlkMC04Y2FlLTQxOGUtODljNy04NjUxZTZhYWIzYzYiLCJlNDQzYWM1OC04ZWNlLTQzODUtOGQ1NS03NzVjMWI4ZjNhMzciLCJBVVRPIiwwLDAsMSwiIiwiIiwiIiwiIiwiIiwiIiwiIiwwLDFd) (hyperlink has user, patients and app URL prefilled)

The launcher is set to launch the app in an iframe, and the app is set to allow the launcher to frame it. Launch the app twice, choosing a different patient each time. Click refresh in each tab to verify they preserve the patient context.

# Setup Other Auth Servers
Copy `config/smart-launch.env`, to create a new `config/<config name>.env` file this instance of your app. This example only supports one auth server/FHIR server at a time.

## Register with Auth Server
Register a client with redirect_uri of `https://localhost/callback` and register a client secret. Add your client_id and client_secret to your .env file as `CLIENT_ID` and `CLIENT_SECRET`.

## Change Cookie Secret
The env file includes anoter secret:
```
...
SECRET=LONG_RANDOM_VALUE
...
```

`SECRET` is how this app signs your cookies. Whenever make a new .env file, '''cnange the SECRET'''. This makes sure that switching the app between multiple auth servers doesn't leave old cookies behind. Try `openssl rand -hex 32` to create a new secret for every server.

## Find OIDC_ISS and FHIR_ISS
The `OIDC_ISS` and `FHIR_ISS` environment variables determine what authorization server and FHIR server (respectively) your app will interact with. 

The `FHIR_ISS` should match the `iss` from the [SMART App Launch](https://hl7.org/fhir/smart-app-launch/1.0.0/#ehr-launch-sequence). It's also known as the FHIR base URL. Some example FHIR_ISS are:
- SMART App Launcher: https://launch.smarthealthit.org/v/r4/fhir
- Epic on FHIR sandbox: https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4 (DSTU2,STU3 also supported)

The `OIDC_ISS` is a bit trickier. This should be the base URL that supports the `/.well-known/openid-configuration` endpoint, which returns the auth server's OIDC metadata. This can vary by auth server, and isn't discoverable. It will also be the `iss` parameter within id_tokens (note, here iss is very different from the FHIR_ISS). Some example OIDC_ISS are:
- SMART App Launcher: https://launch.smarthealthit.org/v/r4/fhir (same as FHIR_ISS)
- Epic on FHIR sandbox: https://fhir.epic.com/interconnect-fhir-oauth/oauth2

## Allowing Framing
This app allows iframing if you provide it with an expected origin in your .env file:
```
...
FRAMER_ORIGIN="https://launch.smarthealthit.org/"
```

This origin can include a wildcard (example: https://*.smarthealthit.org), and is used to populate the X-Frame-Options header or frame-ancestors header, depending on the browser's User-Agent (looking for `Trident`, indicating internet explorer). The following table shows the behavior:
TODO

## Running with Other Config
```
node -r dotenv/config . dotenv_config_path=config/<config name>.env
```