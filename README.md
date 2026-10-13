# PublicWifiScanner

**Educational public WiFi security awareness site featuring simulated risk analysis, safety tips, attack scenarios, and downloadable reports.**

SecureNet demonstrates simulated public WiFi risk profiles. It does not scan or assess real networks.

## Deploy on Netlify

The site runs entirely on Netlify. `netlify.toml` configures the browser assets and Netlify Functions. Only the generated `public` directory is published; Python sources, tests, and private files are not served.

Netlify Identity manages account persistence, passwords, email confirmation, and sessions. The Identity activation marker is included in `.netlify/features/netlify-identity`. Keep registration open in **Project configuration > Identity** if visitors should be able to create accounts. Email confirmation is required by default.

After deployment, open `register.html`, create an account, and follow the confirmation link in your email. Then sign in to use the simulated risk scanner and downloadable reports. Confirmation links are processed on all three pages.

Existing accounts from the former Python backend are not automatically migrated. Register a new Netlify Identity account. The old Python backend files remain for reference, but the current frontend no longer uses them. No separate Python server or database credentials are required.

## Run locally

1. Use Node.js 22 or newer and install dependencies with `npm ci`.
2. Use Netlify CLI with this linked site and Identity enabled.
3. Run `netlify dev --port 8889` and open `http://localhost:8889`.

Opening the HTML files directly or using the old Python server does not provide the required Identity client assets and Netlify Functions.

## API and checks

`GET /health` provides a public health check. `GET /api/me`, `POST /api/risk`, and `POST /api/report` require a valid Netlify Identity session. Risk and report requests accept JSON containing `wifiType` (`open`, `weak`, or `strong`) and require a same-origin browser request. These operations are simulations; they do not store scan results.

Run `npm test` for API and authentication-integration checks, and `npm run typecheck` for the function types. Netlify runs the configured asset build during deployment.

## Before a production launch

The risk numbers are illustrative only, and the app is a student demonstration, not a real security scanner. A public production launch would need stronger operational protections such as monitoring, abuse/rate limiting, account recovery, and privacy disclosures.
