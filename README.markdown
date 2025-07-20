# oldRASHED - OSINT Tool: Wayback Machine Scraper

![Python](https://img.shields.io/badge/Python-3.7%2B-blue.svg)  
![License](https://img.shields.io/badge/License-MIT-green.svg)  
![Version](https://img.shields.io/badge/Version-1.2.0-yellow.svg)

## 📖 Overview

**oldRASHED** is a powerful OSINT (Open-Source Intelligence) tool designed to extract archived URLs from the [Wayback Machine](https://archive.org/web/). It helps security researchers and OSINT enthusiasts by categorizing links, extracting sensitive data like email addresses and API keys, and optionally analyzing JavaScript files for sensitive information. Built with asynchronous programming (`aiohttp` & `asyncio`) and enhanced with precise regex patterns inspired by [Mantra](https://github.com/brosck/mantra), it ensures efficient, accurate, and fast performance with streaming for large files and robust error handling.

## ✨ Features

- **Asynchronous URL Fetching**: Fetches archived URLs using non-blocking I/O with streaming for better performance.
- **Link Categorization**: Organizes URLs by file extensions (e.g., `.js`, `.pdf`, `.txt`, etc.) and sensitive keywords (e.g., `/admin`, `/api`).
- **Sensitive Data Extraction**: Detects email addresses and sensitive data with precise patterns for services like AWS, Google, Slack, Firebase, Twilio, Discord, GitHub, Heroku, Shopify, Stripe, and more.
- **JavaScript Analysis (Optional)**: Asynchronously scans JavaScript files for sensitive data (API keys, tokens, passwords) with Content-Type verification to ensure only JavaScript files are analyzed.
- **Wayback Machine Integration**: Fetches the latest archived snapshots for JavaScript files using the `--way` flag, with improved rate limiting handling (exponential backoff with jitter).
- **Improved Logging**: Detailed logs showing specific leak types, HTTP errors, Content-Type, and file size issues to reduce false positives and debug failures.
- **Customizable Output**: Saves results into categorized files with clear labels for each leak type (all links, emails, sensitive data, JS analysis).
- **CLI Output Control**: Suppress JavaScript analysis output in the CLI with `--quiet-js` while still saving results.
- **Robust Error Handling**: Handles rate limits, timeouts, and failed requests with retries and detailed logging for easier troubleshooting.

## 🛠️ Requirements

- **Python**: Version 3.7 or higher.
- **Dependencies**:
  - `aiohttp`
  - `cachetools`
  - `colorama`
  - `pyfiglet`
  - `validators`

### Install Dependencies

1. Clone the repository or download the script.
2. Install the required libraries using the provided `requirements.txt`:

   ```bash
   pip install -r requirements.txt
   ```

## 🚀 Usage

### Command-Line Options

| Option            | Description                                                                 | Required | Default      |
|-------------------|-----------------------------------------------------------------------------|----------|--------------|
| `-u`, `--url`     | Target domain (e.g., `example.com`).                                       | Yes      | N/A          |
| `-a`, `--analyze-js` | Enable JavaScript file analysis for sensitive data.                    | No       | Disabled     |
| `-o`, `--output`  | Specify the output directory for results.                              | No       | `output`     |
| `--cache`         | Enable caching of fetched links to reduce redundant requests.          | No       | Disabled     |
| `--verbose`       | Enable verbose logging with timestamps for detailed output.            | No       | Disabled     |
| `--quiet-js`      | Suppress JavaScript analysis output in the CLI (results still saved).  | No       | Disabled     |
| `-w`, `--way`     | Fetch JavaScript files from the latest Wayback Machine archives.       | No       | Disabled     |
| `--timeout`       | Timeout for HTTP requests in seconds.                                  | No       | 300          |
| `--retries`       | Number of retries for failed requests.                                 | No       | 3            |
| `--concurrent`    | Max concurrent connections.                                           | No       | 3            |
| `--delay`         | Delay between requests in seconds.                                    | No       | 1.0          |
| `--max-file-size` | Max file size for JS files in MB.                                     | No       | 5            |

### Example Commands

1. **Basic Usage (Fetch and Categorize Links)**:
   ```bash
   python3 oldRASHED.py -u example.com
   ```

2. **With JavaScript Analysis**:
   ```bash
   python3 oldRASHED.py -u example.com -a
   ```

3. **With JavaScript Analysis from Wayback Machine (Latest Snapshots)**:
   ```bash
   python3 oldRASHED.py -u example.com -a -w --timeout 600 --retries 5 --concurrent 3 --delay 1 --max-file-size 5
   ```

4. **Verbose Output with Custom Directory and Quiet JS Analysis**:
   ```bash
   python3 oldRASHED.py -u example.com -a -w -o results --verbose --quiet-js
   ```

### Output Files

Results are saved in the specified output directory (default: `output`). Example files for `example.com`:

- `example.com-all-links.txt`: All fetched URLs.
- `example.com-js.txt`: URLs with `.js` extension.
- `example.com-emails.txt`: URLs containing email addresses.
- `example.com-sensitive-links.txt`: URLs with sensitive keywords, labeled by type (e.g., `[admin]`, `[api]`).
- `example.com-js-analysis.txt`: Results of JavaScript file analysis with detailed leak types (if enabled).
- `example.com-failed-js.txt`: URLs of JavaScript files that failed to fetch or analyze.

## 📜 Example Output

### CLI Output (With `--verbose` and `--way`)
```
oldRASHED
OSINT TOOL - Wayback Machine Scraper
Using timeout of 600 seconds for HTTP requests
Using Wayback Machine archives for JavaScript analysis
Starting data collection for example.com...
Fetched 123 unique links for example.com in 2.34 seconds
Categorizing links...
Categorized 123 links: 5 emails, 10 sensitive links, 15 JS files in 0.12 seconds
Analyzing JavaScript files for sensitive data...
Fetching latest archived URL: https://web.archive.org/web/20230101010101/https://static.example.com/js/app.js
Found sensitive data in https://static.example.com/js/app.js
Analyzed 15 JS files, found sensitive data in 8 files in 5.67 seconds
Saving results...
Saved all links to output/example.com-all-links.txt
Saved sensitive links to output/example.com-sensitive-links.txt
Saved JS analysis to output/example.com-js-analysis.txt
Process completed!
```

### Sensitive Links File (`example.com-sensitive-links.txt`)
```
[admin] https://example.com/admin
[api] https://example.com/api/v1
[query_params] https://example.com/config?key=abc123xyz789
```

### JS Analysis File (`example.com-js-analysis.txt`)
```
https://static.example.com/js/app.js:
  [AWS Access Key] AKIA1234567890ABCDEF
  [Password] password=secret123
https://static.example.com/js/config.js:
  [Google API Key] AIzaSyABC123xyz789-DEFghiJKLm
  [Generic Token] token=abc123xyz789
```

## ⚙️ Setup for Global Access (Optional)

To run `oldRASHED` from anywhere on your system:

1. Make the script executable:
   ```bash
   chmod +x oldRASHED.py
   ```

2. Move the script to a global binary directory (e.g., `/usr/local/bin`):
   ```bash
   sudo mv oldRASHED.py /usr/local/bin/oldrashed
   ```

3. Run the tool from anywhere:
   ```bash
   oldrashed -u example.com -a -w
   ```

## 📝 Notes

- Use `--verbose` with `--way` to debug issues with fetching archived snapshots (e.g., rate limiting or empty snapshots).
- The `--cache` option speeds up repeated scans by caching results for 1 hour.
- The JavaScript analysis uses precise regex patterns inspired by [Mantra](https://github.com/brosck/mantra) to detect specific leaks (e.g., AWS, Slack, Firebase) with reduced false positives.
- Expand the `SENSITIVE_PATTERNS` or `SENSITIVE_LINK_KEYWORDS` dictionaries in the script to add custom regex patterns for specific leak detection.
- The `--way` flag fetches the latest snapshots from Wayback Machine, which may improve results if older snapshots are empty or outdated.
- If no sensitive data is found, check `output/[domain]-failed-js.txt` for failed JavaScript files and use `--verbose` to inspect errors.
- The tool focuses on static analysis of JavaScript files but can be extended to analyze web pages like Mantra.

## 🤝 Contributing

Feel free to fork the repository, make improvements, and submit pull requests. If you encounter bugs or have feature requests, open an issue on GitHub.

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.