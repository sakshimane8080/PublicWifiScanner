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

## Deploy on PythonAnywhere

PythonAnywhere provides a public HTTPS website address for the Flask application. Its exact account and web-app limits depend on the current plan.

1. Create a PythonAnywhere account and open a **Bash console**.
2. Clone the public repository and install its dependencies. Replace `YOUR_USERNAME` with your PythonAnywhere username and choose a Python version available on your account:

   ```bash
   cd ~
   git clone https://github.com/sakshimane8080/PublicWifiScanner.git
   cd ~/PublicWifiScanner
   mkvirtualenv --python=/usr/bin/python3.13 securenet-venv
   pip install -r requirements.txt
   ```

   Select the same Python version when creating the web app. If `/usr/bin/python3.13` is unavailable, use a Python version offered by PythonAnywhere.

3. In the PythonAnywhere **Web** tab, choose **Add a new web app**, then **Manual configuration** and the matching Python version. In the **Virtualenv** section, enter `~/.virtualenvs/securenet-venv`.
4. Open the WSGI configuration file linked on the Web tab. Replace its Flask application section with the following, changing both occurrences of `YOUR_USERNAME` to your PythonAnywhere username:

   ```python
   import os
   import sys

   project_path = "/home/YOUR_USERNAME/PublicWifiScanner"
   if project_path not in sys.path:
       sys.path.insert(0, project_path)

   os.environ["DATABASE_URL"] = "sqlite:////home/YOUR_USERNAME/securenet.sqlite3"
   os.environ["SECURE_COOKIES"] = "true"

   from app import app as application
   ```

5. Save the WSGI file, return to the Web tab, and click **Reload**. Open the web-app URL shown there and register a new account.

The SQLite database is placed in your home directory rather than beside the code, so Git pulls and app reloads do not replace it. Keep the database private and use a unique password. To publish later code changes, push them to GitHub, then run `cd ~/PublicWifiScanner && git pull` in the PythonAnywhere console and reload the web app.

For official provider-specific instructions, see [PythonAnywhere's Flask setup guide](https://help.pythonanywhere.com/pages/Flask/).

## Deploy on Render for a CEP demonstration

1. Put this project in a GitHub repository. Do not add `.env` files, `securenet.sqlite3`, or credentials.
2. In Render, choose **New > Blueprint**, connect the repository, and select its `render.yaml`.
3. Review the services and select the Free plans before confirming creation.
4. Wait for the web service deployment, then visit its `onrender.com` URL and register.

The Blueprint creates a public web service and a managed PostgreSQL database. The service uses HTTPS and secure session cookies on Render. Do not use the Free setup for real customer data: free web services can sleep when idle, and free Render PostgreSQL expires 30 days after creation. Back up anything important and migrate or upgrade before expiration.

## Before a production launch

The risk numbers are illustrative only, and the app is a student demonstration, not a real security scanner. A public production launch would need stronger operational protections such as monitoring, backups, abuse/rate limiting, account recovery, privacy disclosures, and an appropriate paid database plan.
