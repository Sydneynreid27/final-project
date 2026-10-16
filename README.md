# Secret Scanner CLI

This project provides a Python command-line tool that scans a file or directory for common patterns associated with hardcoded secrets, such as API keys, passwords, access tokens, and private keys.

## What it checks

The scanner uses Python's `re` module and looks for several common secret formats, including:

- AWS access keys
- GitHub personal access tokens
- Google API keys
- JWTs
- Private key blocks
- Bearer tokens
- Slack tokens
- Stripe secrets
- Generic password or secret assignments (for example `password=...` or `api_key=...`)

## How it works

1. Accepts a file or directory as input.
2. Recurses through directories while ignoring common generated folders such as `.git`, `venv`, and `__pycache__`.
3. Reads each file line by line.
4. Applies a set of regex patterns to detect suspicious values.
5. Prints findings in the format:
   `filename:line_number: pattern_name: matched_string`
6. Returns a non-zero exit code when secrets are found so it can be used in automated checks.

## Usage

Run the scanner against a single file:

```bash
python3 scan_secrets.py path/to/file.txt
```

Run the scanner against a directory:

```bash
python3 scan_secrets.py path/to/project/
```

Use a different logging level:

```bash
python3 scan_secrets.py path/to/project/ --log-level DEBUG
```

## Example output

```text
Found 3 potential secret(s):
example.env:4: AWS Access Key: AKIA1234567890ABCDEF
example.env:8: Generic Secret: password=supersecretpass
config.py:12: Private Key: -----BEGIN RSA PRIVATE KEY-----
```

## Notes

This tool is intended as a basic security scanner for development and education. It is not a substitute for a full secret-management solution or a production security scanner.
# final-project
