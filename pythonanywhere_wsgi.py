import os


home_directory = os.path.expanduser("~")
database_path = os.path.join(home_directory, "securenet.sqlite3")

os.environ["DATABASE_URL"] = "sqlite:///" + database_path.replace("\\", "/")
os.environ["SECURE_COOKIES"] = "true"

from app import app as application
