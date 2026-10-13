import os

from app import app


if __name__ == "__main__":
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8000"))
    print("SecureNet local server at http://{}:{}".format(host, port), flush=True)
    app.run(host=host, port=port, debug=False)
