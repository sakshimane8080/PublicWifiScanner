# PublicWifiScanner

**Educational public WiFi security awareness site featuring simulated risk analysis, safety tips, attack scenarios, and downloadable reports.**

SecureNet demonstrates simulated public WiFi risk profiles. It does not scan or assess real networks.

## Run locally

1. Install Python 3.12 or newer.
2. From this folder, create and activate a virtual environment.
3. Install dependencies with `pip install -r requirements.txt`.
4. Start the app with `python server.py`.
5. Open `http://127.0.0.1:8000` and register an account.

Local accounts are stored in `securenet.sqlite3`; passwords are hashed before storage.

## Deploy on Render for a CEP demonstration

1. Put this project in a GitHub repository. Do not add `.env` files, `securenet.sqlite3`, or credentials.
2. In Render, choose **New > Blueprint**, connect the repository, and select its `render.yaml`.
3. Review the services and select the Free plans before confirming creation.
4. Wait for the web service deployment, then visit its `onrender.com` URL and register.

The Blueprint creates a public web service and a managed PostgreSQL database. The service uses HTTPS and secure session cookies on Render. Do not use the Free setup for real customer data: free web services can sleep when idle, and free Render PostgreSQL expires 30 days after creation. Back up anything important and migrate or upgrade before expiration.

## Before a production launch

The risk numbers are illustrative only, and the app is a student demonstration, not a real security scanner. A public production launch would need stronger operational protections such as monitoring, backups, abuse/rate limiting, account recovery, privacy disclosures, and an appropriate paid database plan.
