# The corrected version of fixtures/demo_leak.py: nothing secret in the code.
import os

AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]
