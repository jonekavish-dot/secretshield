"""The correct pattern: nothing secret is written in the code.

Values come from the environment. Names (not values) are listed in .env.example.
"""
import os

AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
API_KEY = os.getenv("API_KEY", "")
DATABASE_URL = os.environ["DATABASE_URL"]

# A placeholder in a template is fine: it is not a credential.
EXAMPLE_CONNECTION = "postgresql://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:5432/app"
