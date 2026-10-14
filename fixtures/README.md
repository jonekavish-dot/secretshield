# Test fixtures

Every credential in this folder is **fake**. They exist so the scanner has something
to find during tests and the demo.

| File | What it holds | Why it is safe |
| --- | --- | --- |
| `leaky_config.py` | An AWS-shaped access key, a GitHub-shaped token and a hardcoded password | Invented values that match no real account |
| `safe_config.py` | The same settings read from environment variables | The correct pattern, nothing to find |
| `documented_example.py` | AWS's own published example key | Published by AWS in its public documentation as an example; allowlisted in `.gitleaks.toml` |
| `demo_leak.py` | Two fake credentials, copied into a throwaway repo by the demo script | Invented values; kept here so no key-shaped text sits in `scripts/` |
| `demo_fixed.py` | The corrected version of `demo_leak.py` | Reads from environment variables |

This folder is allowlisted in `.gitleaks.toml`, so the fixtures do not fail our own
pipeline. The scanner is pointed at them explicitly by the test suite and the demo
scripts.

**Never put a real credential here, or anywhere else in this repository.**
