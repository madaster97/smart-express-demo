# smart-express-demo
An example express app supporting SMART on FHIR. Supports multiple browser tabs protected by cookies

# Running the App
Remember `npm install`, of course

```
node -r dotenv/config . dotenv_config_path=config/smart-launch.env
```

Change `smart-launch` to your `<config name>` if you create a new one

# SMART App Launcher Setup
```
https://launch.smarthealthit.org/?auth_error=&fhir_version_2=r4&iss=&launch_ehr=1&launch_url=http%3A%2F%2Flocalhost%3A3000%2Flaunch&patient=67cbf090-4ddb-4799-99ff-a28abe2740b1&prov_skip_auth=1&prov_skip_login=1&provider=e443ac58-8ece-4385-8d55-775c1b8f3a37&pt_skip_auth=1&public_key=&sde=&sim_ehr=1&token_lifetime=15&user_pt=
```

See "Launch App" in the bottom right of that page, after running with default env above

# Setup Other Auth Servers
Copy `config/smart-launch.env`, to create a new `config/<config name>.env` file this instance of your app. This example only supports one auth server/FHIR server at a time.

## Register with Auth Server
Register a client with redirect_uri of `http://localhost:3000/callback` and register a client secret. Add your client_id and client_secret to your .env file

## Change Cookie Secret
The env file includes 2 secrets:
```
SECRET=LONG_RANDOM_VALUE_SMART_LAUNCHER
...
CLIENT_SECRET=YOUR_CLIENT_SECRET
```

`SECRET` is how the server signs your cookies. Whenever make a new .env file, CHANGE SECRET. This makes sure that switching the app between multiple auth servers doesn't leave old cookies behind. Future plans for this example include creating separate paths for each auth server to segregate different sessions.

## Find OIDC_ISS and FHIR_ISS
The `OIDC_ISS` and `FHIR_ISS` environment variables determine what authorization server and FHIR server (respectively) your app will interact with. 

The `FHIR_ISS` should match the `iss` from the [SMART App Launch](https://hl7.org/fhir/smart-app-launch/1.0.0/#ehr-launch-sequence). It's also known as the FHIR base URL. Some example FHIR_ISS are:
- SMART App Launcher: https://launch.smarthealthit.org/v/r4/fhir
- Epic on FHIR sandbox: https://fhir.epic.com/interconnect-fhir-oauth/api/FHIR/R4 (DSTU2,STU3 also supported)

The `OIDC_ISS` is a bit trickier. This should be the base URL that supports the `/.well-known/openid-configuration` endpoint, which returns the auth server's OIDC metadata. This can vary by auth server, and isn't discoverable. It will also be the `iss` parameter within id_tokens (note, here iss is very different from the FHIR_ISS). Some example OIDC_ISS are:
- SMART App Launcher: https://launch.smarthealthit.org/v/r4/fhir (same as FHIR_ISS)
- Epic on FHIR sandbox: https://fhir.epic.com/interconnect-fhir-oauth/oauth2
- Others?

## Running with Other Config
```
node -r dotenv/config . dotenv_config_path=config/<config name>.env
```