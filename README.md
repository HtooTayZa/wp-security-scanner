# WP Security Scanner Pro

An advanced WordPress security scanner with **AI-powered vulnerability analysis** using the Anthropic Claude API.

---

## Features

| Module | What It Tests |
|--------|--------------|
|  SSL/TLS | Certificate validity, HTTPS enforcement, HSTS, HTTP→HTTPS redirect |
|  Security Headers | CSP, X-Frame-Options, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Server header leakage |
|  XSS Detection | Reflected XSS in search & login, DOM XSS sinks (innerHTML, eval, document.write) |
|  SQL Injection | Error-based SQLi probes, wp-config.php exposure, WordPress DB debug mode |
|  Pen Test / Recon | WordPress version disclosure, user enumeration (REST API + ?author=), XML-RPC, sensitive file exposure, directory listing, wp-cron |
|  AI Analysis | Per-finding root cause, realistic attack scenario, detailed code fix, verification steps |

---

## Installation

1. Copy the `wp-security-scanner` folder to `/wp-content/plugins/`
2. Activate the plugin in **Plugins → Installed Plugins**
3. Go to **Security Scanner → Settings** and enter your **API key**
4. Navigate to **Security Scanner** and click **Launch Security Scan**

---

## Requirements

- WordPress 5.8+
- PHP 7.4+
- `openssl` PHP extension (for SSL certificate checks)
- Anthropic API key (for AI analysis — [get one here](https://console.anthropic.com))

---

## Usage

1. Navigate to **Security Scanner** in the WordPress admin sidebar
2. Confirm (or change) the **Target URL**
3. Select which **Test Modules** to run
4. Click **🚀 Launch Security Scan**
5. Review the findings inline, or click **📄 View Full Report** to open the styled HTML report
6. Use **🖨️ Print / Save PDF** in the report viewer to export as PDF

---

## Security Notes

- This plugin is intended for **use on sites you own or have explicit permission to test**.
- All probes are **non-destructive** — they detect vulnerabilities without modifying data.
- Credentials and scan results are stored only in your own WordPress database.
- Your Anthropic API key is stored as a WordPress option (encrypted at rest if you use a security plugin like WP Encryption).

---

## File Structure

```
wp-security-scanner/
├── wp-security-scanner.php          # Main plugin bootstrap
├── uninstall.php                    # Cleanup on deletion
├── includes/
│   ├── class-wpss-database.php      # DB schema & queries
│   ├── class-wpss-scanner.php       # Scan orchestrator
│   ├── class-wpss-tests-ssl.php     # SSL/TLS tests
│   ├── class-wpss-tests-headers.php # Security header tests
│   ├── class-wpss-tests-xss.php     # XSS tests
│   ├── class-wpss-tests-sqli.php    # SQL injection tests
│   ├── class-wpss-tests-pentest.php # Pen test / recon
│   ├── class-wpss-ai-analyzer.php   # Claude AI integration
│   └── class-wpss-report.php        # HTML report generator
├── admin/
│   └── class-wpss-admin.php         # Admin UI & AJAX handlers
└── assets/
    ├── css/admin.css                 # Dark-themed admin styles
    └── js/admin.js                  # Scan UI & report viewer
```

---

## License

GPL-2.0+
