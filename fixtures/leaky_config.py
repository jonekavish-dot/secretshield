"""DUMMY DATA - every value here is fake and matches no real account.

This file is what a careless commit looks like. The scanner should flag
every credential below. See fixtures/safe_config.py for the correct version.
"""

# Fake AWS credentials (invented; not AWS's documented example, so the scanner flags them)
AWS_ACCESS_KEY_ID = "AKIA4SHIELDDEMO7QZXK"
aws_secret_access_key = "Kp7xQm2LvR9tNw4ZbY6cFj8HsA3dEg5TuV1nMx0W"

# Fake GitHub personal access token
GITHUB_TOKEN = "ghp_1A2b3C4d5E6f7G8h9I0jK1L2m3N4o5P6q7R8"

# Fake third-party API key
api_key = "sk_test_4eC39HqLyjWDarjtT1zdp7dc0000"

# Hardcoded password
password = "SuperSecret123!"

DATABASE_URL = "postgresql://admin:hunter2pass@db.internal:5432/app"
