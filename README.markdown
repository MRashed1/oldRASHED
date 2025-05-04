# oldRASHED - OSINT Tool: Wayback Machine Scraper

![Python](https://img.shields.io/badge/Python-3.7%2B-blue.svg)  
![License](https://img.shields.io/badge/License-MIT-green.svg)  
![Version](https://img.shields.io/badge/Version-1.0.0-yellow.svg)

## 📖 Overview

**oldRASHED** is a powerful OSINT (Open-Source Intelligence) tool designed to extract archived URLs from the [Wayback Machine](https://archive.org/web/). It helps security researchers and OSINT enthusiasts by categorizing links, extracting sensitive data like email addresses and keywords, and optionally analyzing JavaScript files for sensitive information. Built with asynchronous programming (`aiohttp` & `asyncio`), it ensures efficient and fast performance.

## ✨ Features

- **Asynchronous URL Fetching**: Fetches archived URLs using non-blocking I/O for better performance.
- **Link Categorization**: Organizes URLs by file extensions (e.g., `.js`, `.pdf`, `.txt`, etc.).
- **Sensitive Data Extraction**: Detects email addresses and sensitive keywords (e.g., `api_key`, `password`).
- **JavaScript Analysis (Optional)**: Asynchronously scans JavaScript files for sensitive information.
- **Customizable Output**: Saves results into categorized files (all links, emails, sensitive data, JS analysis).
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
- `example.com-sensitive.txt`: URLs with sensitive keywords.
- `example.com-js-analysis.txt`: Results of JavaScript file analysis (if enabled).

## 📜 Example Output

### CLI Output (With `--quiet-js`)
```
oldRASHED
OSINT TOOL - Wayback Machine Scraper
Starting data collection for example.com...
Fetched 123 unique links for example.com...
Categorizing links...
Categorized 123 links: 5 emails, 10 sensitive, 15 JS files
Analyzing JavaScript files for sensitive data...
Analyzed 15 JS files, found sensitive data in 8 files
Saving results...
Saved all links to output/example.com-all-links.txt
Saved JS analysis to output/example.com-js-analysis.txt
Process completed!
```

### JS Analysis File (`example.com-js-analysis.txt`)
```
https://static.example.com/js/app.js -> password, auth, key
https://static.example.com/js/config.js -> token, secret
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
- Ensure you have proper permissions when moving the script to a global directory.

## 🤝 Contributing

Feel free to fork the repository, make improvements, and submit pull requests. If you encounter bugs or have feature requests, open an issue on GitHub.

