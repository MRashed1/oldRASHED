# oldRASHED - OSINT Tool: Wayback Machine Scraper

![Python](https://img.shields.io/badge/Python-3.7%2B-blue.svg)  
![License](https://img.shields.io/badge/License-MIT-green.svg)  
![Version](https://img.shields.io/badge/Version-1.1.0-yellow.svg)

## 📖 Overview

**oldRASHED** is a powerful OSINT (Open-Source Intelligence) tool designed to extract archived URLs from the [Wayback Machine](https://archive.org/web/). It helps security researchers and OSINT enthusiasts by categorizing links, extracting sensitive data like email addresses and API keys, and optionally analyzing JavaScript files for sensitive information. Built with asynchronous programming (`aiohttp` & `asyncio`) and enhanced with precise regex patterns inspired by [Mantra](https://github.com/brosck/mantra), it ensures efficient, accurate, and fast performance.

## ✨ Features

- **Asynchronous URL Fetching**: Fetches archived URLs using non-blocking I/O for better performance.
- **Link Categorization**: Organizes URLs by file extensions (e.g., `.js`, `.pdf`, `.txt`, etc.).
- **Sensitive Data Extraction**: Detects email addresses and sensitive data with precise patterns for services like AWS, Google, Slack, Firebase, Twilio, Discord, GitHub, Heroku, Shopify, Stripe, and more.
- **JavaScript Analysis (Optional)**: Asynchronously scans JavaScript files for sensitive data, including API keys, tokens, passwords, and credit card patterns, with detailed logging.
- **Improved Logging**: Clear, structured logs inspired by Mantra, showing specific leak types (e.g., "AWS Access Key", "Slack Token") to reduce false positives.
- **Customizable Output**: Saves results into categorized files with clear labels for each leak type (all links, emails, sensitive data, JS analysis).
- **CLI Output Control**: Suppress JavaScript analysis output in the CLI with `--quiet-js` while still saving results.

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

| Option          | Description                                                                 | Required | Default      |
|-----------------|-----------------------------------------------------------------------------|----------|--------------|
| `-u`, `--url`   | Target domain (e.g., `example.com`).                                       | Yes      | N/A          |
| `-a`, `--analyze-js` | Enable JavaScript file analysis for sensitive data.                    | No       | Disabled     |
| `-o`, `--output` | Specify the output directory for results.                              | No       | `output`     |
| `--cache`       | Enable caching of fetched links to reduce redundant requests.          | No       | Disabled     |
| `--verbose`     | Enable verbose logging with timestamps for detailed output.            | No       | Disabled     |
| `--quiet-js`    | Suppress JavaScript analysis output in the CLI (results still saved).  | No       | Disabled     |

### Example Commands

1. **Basic Usage (Fetch and Categorize Links)**:
   ```bash
   python3 oldRASHED.py -u example.com
   ```

2. **With JavaScript Analysis**:
   ```bash
   python3 oldRASHED.py -u example.com -a
   ```

3. **With JavaScript Analysis (Quiet Mode)**:
   ```bash
   python3 oldRASHED.py -u example.com -a --quiet-js
   ```

4. **Verbose Output with Custom Directory**:
   ```bash
   python3 oldRASHED.py -u example.com -a -o results --verbose
   ```

### Output Files

Results are saved in the specified output directory (default: `output`). Example files for `example.com`:

- `example.com-all-links.txt`: All fetched URLs.
- `example.com-js.txt`: URLs with `.js` extension.
- `example.com-emails.txt`: URLs containing email addresses.
- `example.com-sensitive.txt`: URLs with sensitive data, labeled by leak type (e.g., `[AWS Access Key]`).
- `example.com-js-analysis.txt`: Results of JavaScript file analysis with detailed leak types (if enabled).

## 📜 Example Output

### CLI Output (With `--quiet-js`)
```
oldRASHED
OSINT TOOL - Wayback Machine Scraper
Starting data collection for example.com...
Fetched 123 unique links for example.com...
Categorizing links...
Categorized 123 links: 5 emails, 10 sensitive matches, 15 JS files
Analyzing JavaScript files for sensitive data...
Analyzed 15 JS files, found sensitive data in 8 files
Saving results...
Saved all links to output/example.com-all-links.txt
Saved sensitive matches to output/example.com-sensitive.txt
Saved JS analysis to output/example.com-js-analysis.txt
Process completed!
```

### Sensitive Data File (`example.com-sensitive.txt`)
```
[AWS Access Key] https://example.com/config?key=AKIA1234567890ABCDEF -> AKIA1234567890ABCDEF
[Slack Token] https://example.com/js/app.js?token=xoxb-1234567890 -> xoxb-1234567890
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
   oldrashed -u example.com -a
   ```

## 📝 Notes

- Use `--verbose` for detailed logs if you encounter issues.
- The `--cache` option helps speed up repeated scans by caching results for 1 hour.
- The JavaScript analysis uses precise regex patterns inspired by [Mantra](https://github.com/brosck/mantra) to detect specific leaks (e.g., AWS, Slack, Firebase) with reduced false positives.
- Expand the `SENSITIVE_PATTERNS` dictionary in the script to add new regex patterns for custom leak detection.
- The tool focuses on static analysis of JavaScript files but can be extended to analyze web pages like Mantra.

## 🤝 Contributing

Feel free to fork the repository, make improvements, and submit pull requests. If you encounter bugs or have feature requests, open an issue on GitHub.

## 📜 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.