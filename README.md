# Checkmarx One API Example

A minimal, self-contained Python script (`example.py`) that:

1. Reads connection details from `config.json`.
2. Generates an OAuth access token with your Checkmarx One tenant.
3. Calls the `/results` endpoint and prints a short summary of each project.

The goal is to give customers a clear, working reference with as little boilerplate as possible.

---

## Repository layout

```
.
├── get_scan_results.py           # Main demo script
├── utils/
│   └── generate_oauth_token.py
├── config.json          # Tenant-specific settings (never commit credentials)
└── requirements.txt     # Python dependencies
```

---

## Prerequisites

* **Python 3.8+** (tested on 3.8-3.12)
* Internet access to your Checkmarx One region

---

## Installation

```bash
# 1) Clone or download this repository
git clone https://github.com/your-org/checkmarx-api-demo.git
cd checkmarx-api-demo

# 2) Install dependencies
pip install -r requirements.txt
```

`requirements.txt` contains only the libraries required for the demo (currently `requests`).

---

## Configuration

**Use your specific scan ids in the main function**

Edit **`config.json`**:

```json
{
  "api_url":    "https://us.ast.checkmarx.net/api",
  "iam_url":    "https://us.iam.checkmarx.net/auth/realms/",
  "api_key":    "REPLACE_ME",
  "tenant_name": "REPLACE_ME"
}
```

* `api_url` – Base of the public Checkmarx One API for your region.  
* `iam_url` – Identity endpoint (realm root).  
* `api_key` – Your personal or service API key.  
* `tenant_name` – Exact tenant as shown in the Checkmarx One UI.

**Never** commit real API keys or tokens to source control.

---

## Running the demo

```bash
python get_scan_results.py
```

## Troubleshooting

| Issue | Resolution |
|-------|------------|
| `api_url missing in config.json` | Verify the key exists and is spelled correctly. |
| `Could not obtain OAuth token.` | Check `api_key` and `tenant_name`; ensure IAM URL is correct for your region. |
| `Project request failed: <error>` | Confirm network access to the `api_url`; ensure the token is still valid. |

Enable more verbose logs by changing `logging.basicConfig(level=logging.DEBUG, …)` inside `example.py`.


