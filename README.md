# Simple-Web-Tester
A minimal script to test a Web application for basic security vulnerabilities.

* Disclaimer: This script performs active requests

## How to Use

### 1. Clone this repository
```bash
git clone https://github.com/chimms1/Simple-Web-Tester.git
cd Simple-Web-Tester
```

### 2. Install requirements
```bash
pip install requests beautifulsoup4
```


### 3. Run the script
```bash
python main.py --base http://localhost:3000/ --username bee --password buggy --max-pages 300 --delay 0.5
```

### Optional arguments (may not work):
| Flag | Description |
|------|--------------|
| `--insecure` | Disable SSL verification (useful for self-signed certs) |
| `--exclude` | Regex patterns to skip specific URLs |
| `--report-file` | Output report file name (default: `scanner_report.txt`) |
| `--max-pages` | Limit number of pages to crawl (default: 500) |
| `--delay` | Delay between requests in seconds (default: 0.5s) |

---

## About This Script

### Automatic Login
- The script automatically detects and submits login forms using the provided `--username` and `--password`.
- Once authenticated, it continues crawling as a logged-in user.

---

### Web Crawler
- Crawls the entire web app, following only **same-domain** links.
- Collects all forms and GET parameters for active testing.
- Skips non-HTML resources and respects `--exclude` patterns.

---

### Vulnerability Tests

#### 1. **CSRF Detection (Active)**
- Detects **forms or requests that change state** (POST, PUT, DELETE, etc.).
- Sends each request **twice**:
  - Once normally.
  - Once with all **CSRF tokens removed**.
- If both responses are similar (status + content), it's flagged as **likely missing CSRF protection**.

#### 2. **SQL Injection**
- Tests both **GET** and **POST** parameters with common SQL payloads (`' OR 1=1--`, etc.).
- Looks for:
  - SQL error messages in responses.
  - Response differences from baseline.
  - Successful authentication bypass on login forms.

#### 3. **Reflected XSS**
- Injects harmless JavaScript payloads (like `<script>alert("XSS-Scanner-Probe")</script>`) into form fields and URL parameters.
- Flags pages where payloads are reflected unencoded in the HTML response.

#### 4. **OS Command Injection (CMDi)**
- Injects **safe echo-based payloads** like `; echo CMD_INJECTED_42` into parameters.
- Checks if the response contains the marker, indicating possible command execution.
- Also includes **passive detection** of suspicious parameters (e.g. `cmd=`, `exec=`, etc.).

---

### Reporting
- Generates a detailed text report (`scanner_report.txt` by default).
- Contains:
  - All visited URLs.
  - Vulnerabilities grouped by type.
  - JSON-formatted details for each finding.

Example snippet from report:
```
--- Vulnerability 3 ---
{
  "type": "sqli-login",
  "page": "http://localhost:3000/login",
  "parameter": "username",
  "payload": "' OR '1'='1",
  "detail": "Login-like success indicator found after injection (possible login bypass)."
}
```

---