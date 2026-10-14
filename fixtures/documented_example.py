"""AWS's own published example credentials.

These exact strings appear throughout AWS's public documentation as examples.
They authenticate nothing. The allowlist in .gitleaks.toml covers them, which is
how SecretShield avoids crying wolf over well-known documentation values.
"""

# From the AWS CLI documentation
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Obvious placeholders a developer is meant to replace
API_KEY = "your_api_key_here"
TOKEN = "changeme"
