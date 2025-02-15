# oldRASHED - OSINT Tool: Wayback Machine Scraper

## Description
oldRASHED is an OSINT tool designed to extract archived URLs from the [Wayback Machine](https://archive.org/web/). It categorizes links by file type, extracts email addresses and sensitive data, and (optionally) analyzes JavaScript files for sensitive information. The tool leverages asynchronous programming (`aiohttp` & `asyncio`) to improve performance.

## Features
- **Asynchronous URL Fetching:** Efficiently fetches archived URLs using non-blocking I/O.
- **Link Categorization:** Organizes URLs based on file extensions (e.g., js, pdf, txt, etc.).
- **Sensitive Data Extraction:** Detects and extracts email addresses and sensitive keywords.
- **JavaScript Analysis (Optional):** Asynchronously analyzes JavaScript files for sensitive information.
- **Output Files:** Saves results in separate files for all links, categorized links, emails, sensitive data, and JavaScript analysis.

## Requirements
- **Python:** Version 3.7 or higher is required.
- **Required Libraries:**
  - `aiohttp`
  - `requests`
  - `colorama`
  - `pyfiglet`

Install the libraries using pip:
```bash
pip install aiohttp requests colorama pyfiglet


chmod +x oldrashed.py


Move the Script to a Global Binary Directory: Move the script to /usr/local/bin (or any directory in your PATH) so you can run it from anywhere:

sudo mv oldrashed.py /usr/local/bin/oldrashed

Run the Tool: 

oldrashed -u example.com -a

Usage
Command-Line Options
-u, --url
(Required) Target domain (e.g., example.com).

-a, --analyze-js
(Optional) Enable JavaScript file analysis for sensitive data.

-o, --output
(Optional) Specify an output directory (default: output).