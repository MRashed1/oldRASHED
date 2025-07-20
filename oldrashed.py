#!/usr/bin/env python3
import os
import aiohttp
import asyncio
import re
import argparse
import logging
import validators
import cachetools
from urllib.parse import urlparse
from collections import defaultdict
from colorama import Fore, Style, init
import pyfiglet
import json
import time

# Initialize colorama
init(autoreset=True)

# Setup logging
def setup_logging(verbose: bool) -> None:
    """Configure logging with simple or verbose format based on user input."""
    log_format = "%(message)s" if not verbose else "%(asctime)s [%(levelname)s] %(message)s"
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format=log_format,
        handlers=[logging.StreamHandler()]
    )

# Initialize caches
cache = cachetools.TTLCache(maxsize=100, ttl=3600)  # Cache for domains (1 hour)
js_cache = cachetools.TTLCache(maxsize=1000, ttl=3600)  # Cache for JS file contents
failed_js_cache = cachetools.TTLCache(maxsize=1000, ttl=3600)  # Cache for failed JS fetches

# Regex patterns for sensitive data in JavaScript files (enhanced for JS analysis)
SENSITIVE_PATTERNS = {
    "aws_access_key": (re.compile(r'(?i)(aws_?access_key_id|AKIA|ASIA)[0-9A-Z]{16}', re.IGNORECASE), "AWS Access Key"),
    "google_api_key": (re.compile(r'(?i)AIza[0-9A-Za-z\-_]{35}', re.IGNORECASE), "Google API Key"),
    "google_oauth": (re.compile(r'(?i)[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', re.IGNORECASE), "Google OAuth Key"),
    "slack_token": (re.compile(r'(?i)xox[baprs]-[0-9A-Za-z\-]{10,48}', re.IGNORECASE), "Slack Token"),
    "firebase": (re.compile(r'(?i)AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}', re.IGNORECASE), "Firebase Key"),
    "twilio": (re.compile(r'(?i)SK[0-9a-fA-F]{32}', re.IGNORECASE), "Twilio Key"),
    "discord_token": (re.compile(r'(?i)[0-9A-Za-z]{24}\.[0-9A-Za-z]{6}\.[A-Za-z0-9-_]{27}', re.IGNORECASE), "Discord Token"),
    "github_token": (re.compile(r'(?i)(ghp_|gho_|ghu_|ghs_|ghr_)[0-9A-Za-z]{36}', re.IGNORECASE), "GitHub Token"),
    "heroku_api_key": (re.compile(r'(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE), "Heroku API Key"),
    "shopify_token": (re.compile(r'(?i)shpat_[0-9a-f]{32}', re.IGNORECASE), "Shopify Token"),
    "stripe_key": (re.compile(r'(?i)(sk|pk)_live_[0-9A-Za-z]{24}', re.IGNORECASE), "Stripe Key"),
    "slack_webhook": (re.compile(r'(?i)https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+', re.IGNORECASE), "Slack Webhook"),
    "jwt": (re.compile(r'(?i)eyJ[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{20,}\.[A-Za-z0-9-_]{20,}', re.IGNORECASE), "JSON Web Token"),
    "password": (re.compile(r'(?i)(password|pass|pwd|credential)=[\'"]?[A-Za-z0-9!@#$%^&*]{8,}[\'"]?', re.IGNORECASE), "Password"),
    "json_secret": (re.compile(r'(?i){\s*[\'"]?(api_key|token|secret|access_token|refresh_token|key|password)[\'"]?:\s*[\'"][A-Za-z0-9_-]{20,}[\'"]', re.IGNORECASE), "JSON Secret"),
    "url_secret": (re.compile(r'(?i)https?://[A-Za-z0-9_-]+\:[A-Za-z0-9_-]+@[A-Za-z0-9.-]+', re.IGNORECASE), "URL with Credentials"),
    "generic_key": (re.compile(r'(?i)(api_?key|key|secret|token)=[\'"]?[A-Za-z0-9+/=]{20,}[\'"]?', re.IGNORECASE), "Generic Key"),
    "bearer_token": (re.compile(r'(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}', re.IGNORECASE), "Bearer Token"),
    "private_key": (re.compile(r'(?i)-----BEGIN\s+(RSA|OPENSSH|EC)\s+PRIVATE\s+KEY-----\n[A-Za-z0-9+/=\n]+-----END\s+(RSA|OPENSSH|EC)\s+PRIVATE\s+KEY-----', re.IGNORECASE), "Private Key")
}

# Keywords and patterns for identifying sensitive links (not using JS regex)
SENSITIVE_LINK_KEYWORDS = {
    "admin": r'(?i)/admin/?',
    "api": r'(?i)/api/?',
    "auth": r'(?i)/auth(entication|orization)?/?',
    "login": r'(?i)/login/?',
    "key": r'(?i)/key(s)?/?',
    "secret": r'(?i)/secret(s)?/?',
    "config": r'(?i)/config(uration)?/?',
    "env": r'(?i)\.env(\.bak|\.old)?$',
    "backup": r'(?i)\.(bak|backup|old)$',
    "credentials": r'(?i)/cred(ential)?s/?',
    "token": r'(?i)/token(s)?/?',
    "private": r'(?i)/private/?',
    "secure": r'(?i)/secure/?',
    "dashboard": r'(?i)/dashboard/?',
    "query_params": r'(?i)\?(key|token|secret|api_key|access_token|password)=[A-Za-z0-9_-]+'
}

async def fetch_wayback_links(domain: str, retries: int = 3, timeout: int = 300) -> list[str]:
    """Fetch unique URLs from Wayback Machine for a given domain with retry mechanism."""
    start_time = time.time()
    domain = clean_filename(domain)
    if domain in cache:
        logger.info(f"{Fore.YELLOW}Returning cached links for {domain}{Style.RESET_ALL}")
        return cache[domain]

    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&collapse=urlkey&output=text&fl=original"
    
    for attempt in range(retries):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=timeout) as response:
                    if response.status == 200:
                        text = await response.text()
                        links = list(set(text.splitlines()))
                        cache[domain] = links
                        logger.info(f"{Fore.GREEN}Fetched {len(links)} unique links for {domain} in {time.time() - start_time:.2f} seconds{Style.RESET_ALL}")
                        return links
                    else:
                        logger.error(f"{Fore.RED}Failed to fetch links for {domain}: HTTP {response.status}{Style.RESET_ALL}")
                        return []
        except aiohttp.ClientError as e:
            logger.error(f"{Fore.RED}Attempt {attempt + 1}/{retries} - Network error while fetching links for {domain}: {e}{Style.RESET_ALL}")
            logger.debug(f"{Fore.YELLOW}Details: {type(e).__name__} - {str(e)}{Style.RESET_ALL}")
            if attempt == retries - 1:
                logger.error(f"{Fore.RED}All attempts failed. Check your internet connection or try again later.{Style.RESET_ALL}")
                return []
            await asyncio.sleep(2 ** attempt)
        except asyncio.TimeoutError:
            logger.error(f"{Fore.RED}Attempt {attempt + 1}/{retries} - Timeout while fetching links for {domain}{Style.RESET_ALL}")
            if attempt == retries - 1:
                logger.error(f"{Fore.RED}All attempts failed due to timeout.{Style.RESET_ALL}")
                return []
            await asyncio.sleep(2 ** attempt)
    logger.info(f"{Fore.YELLOW}Total time for fetching links: {time.time() - start_time:.2f} seconds{Style.RESET_ALL}")

def categorize_links(links: list[str]) -> tuple[defaultdict, list[str], dict[str, list[str]], list[str]]:
    """Categorize URLs based on file extensions, emails, and sensitive keywords."""
    start_time = time.time()
    file_extensions = re.compile(
        r'.*\.(js|xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|git|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|apk|msi|env|dmg|tmp|crt|pem|key|pub|asc)$',
        re.IGNORECASE
    )
    email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    categorized = defaultdict(list)
    email_links = []
    sensitive_links = defaultdict(list)
    js_files = []

    for link in links:
        if email_pattern.search(link):
            email_links.append(link)
        for keyword_name, pattern in SENSITIVE_LINK_KEYWORDS.items():
            if re.search(pattern, link):
                sensitive_links[keyword_name].append(link)
        match = file_extensions.search(link)
        if match:
            ext = match.group(1).lower()
            categorized[ext].append(link)
            if ext == "js":
                js_files.append(link)
                if len(js_files) <= 5:
                    logger.debug(f"{Fore.CYAN}Found JS file: {link}{Style.RESET_ALL}")

    if not js_files:
        logger.warning(f"{Fore.YELLOW}No JavaScript files (.js) found in the categorized links.{Style.RESET_ALL}")

    logger.info(f"{Fore.GREEN}Categorized {len(links)} links: {len(email_links)} emails, {sum(len(links) for links in sensitive_links.values())} sensitive links, {len(js_files)} JS files in {time.time() - start_time:.2f} seconds{Style.RESET_ALL}")
    return categorized, email_links, sensitive_links, js_files

async def analyze_js_files(js_links: list[str], quiet_js: bool, use_wayback: bool, timeout: int, max_file_size: int = 5 * 1024 * 1024) -> list[tuple[str, dict[str, set[str]]]]:
    """Analyze JavaScript files for sensitive data with streaming and size check."""
    start_time = time.time()
    results = []
    failed_js = []

    async def fetch_js(url: str, session: aiohttp.ClientSession) -> tuple[str, dict[str, set[str]]] | None:
        if url in js_cache:
            logger.debug(f"{Fore.YELLOW}Returning cached JS analysis for {url}{Style.RESET_ALL}")
            return js_cache[url]
        if url in failed_js_cache:
            logger.debug(f"{Fore.YELLOW}Skipping previously failed JS file: {url}{Style.RESET_ALL}")
            return None

        try:
            # Check file size before downloading
            async with session.head(url, timeout=timeout // 2) as head_response:
                if head_response.status == 200:
                    content_length = head_response.headers.get('Content-Length')
                    if content_length and int(content_length) > max_file_size:
                        logger.warning(f"{Fore.YELLOW}Skipping {url}: File size {content_length} bytes exceeds limit {max_file_size}{Style.RESET_ALL}")
                        failed_js_cache[url] = True
                        failed_js.append(url)
                        return None

            # Stream the content
            fetch_url = url
            if use_wayback:
                cdx_url = f"https://web.archive.org/cdx/search/cdx?url={url}&output=json&fl=timestamp,original"
                async with session.get(cdx_url, timeout=timeout // 2) as cdx_response:
                    if cdx_response.status == 200:
                        cdx_data = await cdx_response.json()
                        snapshots = [item for item in cdx_data[1:] if item[0]]
                        if snapshots:
                            oldest_snapshot = min(snapshots, key=lambda x: x[0])
                            fetch_url = f"https://web.archive.org/web/{oldest_snapshot[0]}/{oldest_snapshot[1]}"
                            logger.debug(f"{Fore.CYAN}Fetching oldest archived URL: {fetch_url}{Style.RESET_ALL}")
                        else:
                            logger.warning(f"{Fore.YELLOW}No snapshots found for {url} in Wayback Machine{Style.RESET_ALL}")
                            failed_js_cache[url] = True
                            failed_js.append(url)
                            return None
                    else:
                        logger.warning(f"{Fore.YELLOW}Failed to query Wayback CDX for {url}: HTTP {cdx_response.status}{Style.RESET_ALL}")
                        failed_js_cache[url] = True
                        failed_js.append(url)
                        return None

            logger.debug(f"{Fore.CYAN}Fetching JS file: {fetch_url}{Style.RESET_ALL}")
            async with session.get(fetch_url, timeout=timeout) as response:
                if response.status != 200:
                    logger.warning(f"{Fore.YELLOW}Failed to fetch {fetch_url}: HTTP {response.status}{Style.RESET_ALL}")
                    failed_js_cache[url] = True
                    failed_js.append(url)
                    return None

                # Stream content in chunks
                text = ""
                async for chunk in response.content.iter_chunked(1024 * 1024):  # 1MB chunks
                    text += chunk.decode('utf-8', errors='ignore')
                
                if not text.strip():
                    logger.warning(f"{Fore.YELLOW}Empty content fetched for {fetch_url}{Style.RESET_ALL}")
                    failed_js_cache[url] = True
                    failed_js.append(url)
                    return None

                matches = {}
                for pattern_name, (pattern, description) in SENSITIVE_PATTERNS.items():
                    found = set(pattern.findall(text))
                    if found:
                        matches[pattern_name] = found
                if matches:
                    if not quiet_js:
                        logger.info(f"{Fore.MAGENTA}Found sensitive data in {url}: {json.dumps(matches, indent=2)}{Style.RESET_ALL}")
                    js_cache[url] = (url, matches)
                    return url, matches
                js_cache[url] = None
                logger.debug(f"{Fore.YELLOW}No sensitive data found in {url}{Style.RESET_ALL}")
                return None
        except aiohttp.ClientError as e:
            logger.warning(f"{Fore.YELLOW}Failed to analyze {url}: {str(e)}{Style.RESET_ALL}")
            failed_js_cache[url] = True
            failed_js.append(url)
            return None
        except asyncio.TimeoutError:
            logger.warning(f"{Fore.YELLOW}Timeout while fetching {url}{Style.RESET_ALL}")
            failed_js_cache[url] = True
            failed_js.append(url)
            return None

    connector = aiohttp.TCPConnector(limit=3)  # Reduced for better performance
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fetch_js(url, session) for url in js_links]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        for res in responses:
            if res and not isinstance(res, Exception):
                results.append(res)

    if failed_js:
        domain_filename = clean_filename(js_links[0] if js_links else 'unknown')
        with open(f"output/{domain_filename}-failed-js.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(failed_js))
        logger.info(f"{Fore.YELLOW}Saved {len(failed_js)} failed JS URLs to output/{domain_filename}-failed-js.txt{Style.RESET_ALL}")

    logger.info(f"{Fore.GREEN}Analyzed {len(js_links)} JS files, found sensitive data in {len(results)} files in {time.time() - start_time:.2f} seconds{Style.RESET_ALL}")
    return results

def clean_filename(domain: str) -> str:
    """Clean domain name to create a safe filename."""
    parsed = urlparse(domain if domain.startswith(('http://', 'https://')) else f'http://{domain}')
    domain_clean = parsed.netloc or domain
    domain_clean = re.sub(r'[^\w\-\.]', '_', domain_clean)
    return domain_clean

def save_results(
    output_folder: str,
    domain: str,
    categorized_links: defaultdict,
    email_links: list[str],
    sensitive_links: dict[str, list[str]],
    js_analysis: list[tuple[str, dict[str, set[str]]]],
    all_links: list[str]
) -> None:
    """Save categorized links and analysis results to files."""
    start_time = time.time()
    os.makedirs(output_folder, exist_ok=True)
    domain_filename = clean_filename(domain)

    with open(f"{output_folder}/{domain_filename}-all-links.txt", "w", encoding="utf-8") as file:
        file.write("\n".join(sorted(set(all_links))))
    logger.info(f"{Fore.BLUE}Saved all links to {output_folder}/{domain_filename}-all-links.txt{Style.RESET_ALL}")

    for ext, links in categorized_links.items():
        filename = f"{output_folder}/{domain_filename}-{ext}.txt"
        with open(filename, "w", encoding="utf-8") as file:
            file.write("\n".join(links))
        logger.info(f"{Fore.CYAN}Saved {ext} links to {filename}{Style.RESET_ALL}")

    if email_links:
        with open(f"{output_folder}/{domain_filename}-emails.txt", "w", encoding="utf-8") as file:
            file.write("\n".join(email_links))
        logger.info(f"{Fore.YELLOW}Saved email links to {output_folder}/{domain_filename}-emails.txt{Style.RESET_ALL}")

    if sensitive_links:
        with open(f"{output_folder}/{domain_filename}-sensitive-links.txt", "w", encoding="utf-8") as file:
            for keyword_name, links in sensitive_links.items():
                for link in links:
                    file.write(f"[{keyword_name}] {link}\n")
        logger.info(f"{Fore.RED}Saved sensitive links to {output_folder}/{domain_filename}-sensitive-links.txt{Style.RESET_ALL}")

    if js_analysis:
        with open(f"{output_folder}/{domain_filename}-js-analysis.txt", "w", encoding="utf-8") as file:
            for url, matches in js_analysis:
                file.write(f"{url}:\n")
                for pattern_name, found in matches.items():
                    file.write(f"  [{SENSITIVE_PATTERNS[pattern_name][1]}] {', '.join(found)}\n")
        logger.info(f"{Fore.MAGENTA}Saved JS analysis to {output_folder}/{domain_filename}-js-analysis.txt{Style.RESET_ALL}")

    logger.info(f"{Fore.GREEN}Results saved in {time.time() - start_time:.2f} seconds{Style.RESET_ALL}")

async def main() -> None:
    """Main function to orchestrate the OSINT tool workflow."""
    parser = argparse.ArgumentParser(description="oldRASHED - OSINT TOOL for extracting URLs from Wayback Machine. Use -h to see this help message and exit.")
    parser.add_argument("-u", "--url", required=True, help="Target domain (e.g., example.com)")
    parser.add_argument("-a", "--analyze-js", action="store_true", help="Enable JavaScript file analysis")
    parser.add_argument("-o", "--output", default="output", help="Output directory (default: output)")
    parser.add_argument("--cache", action="store_true", help="Enable caching of fetched links")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging with timestamps")
    parser.add_argument("--quiet-js", action="store_true", help="Suppress JS analysis output in CLI (results still saved)")
    parser.add_argument("-w", "--way", action="store_true", help="Fetch JavaScript files from Wayback Machine archives instead of original servers")
    parser.add_argument("--timeout", type=int, default=300, help="Timeout for HTTP requests in seconds (default: 300)")
    parser.add_argument("--retries", type=int, default=3, help="Number of retries for failed requests (default: 3)")
    parser.add_argument("--concurrent", type=int, default=3, help="Max concurrent connections (default: 3)")
    parser.add_argument("--delay", type=float, default=1.0, help="Delay between requests in seconds (default: 1.0)")
    parser.add_argument("--max-file-size", type=int, default=5, help="Max file size for JS files in MB (default: 5)")

    args = parser.parse_args()
    domain = args.url
    output_folder = args.output
    use_wayback = args.way
    timeout = args.timeout
    max_file_size = args.max_file_size * 1024 * 1024  # Convert MB to bytes

    setup_logging(args.verbose)
    global logger
    logger = logging.getLogger(__name__)

    logo = pyfiglet.figlet_format("oldRASHED")
    logger.info(f"{Fore.RED}{logo}{Style.RESET_ALL}")
    logger.info(f"{Fore.CYAN}OSINT TOOL - Wayback Machine Scraper{Style.RESET_ALL}")
    logger.info(f"{Fore.CYAN}Using timeout of {timeout} seconds for HTTP requests{Style.RESET_ALL}")
    if use_wayback:
        logger.info(f"{Fore.CYAN}Using Wayback Machine archives for JavaScript analysis{Style.RESET_ALL}")

    if not validators.domain(domain) and not validators.url(domain):
        logger.error(f"{Fore.RED}Invalid domain or URL: {domain}{Style.RESET_ALL}")
        return

    logger.info(f"{Fore.GREEN}Starting data collection for {domain}{Style.RESET_ALL}")
    links = await fetch_wayback_links(domain, args.retries, timeout)
    if not links:
        logger.warning(f"{Fore.YELLOW}No links found!{Style.RESET_ALL}")
        return

    logger.info(f"{Fore.GREEN}Categorizing links...{Style.RESET_ALL}")
    categorized_links, email_links, sensitive_links, js_files = categorize_links(links)

    js_analysis = []
    if args.analyze_js and js_files:
        logger.info(f"{Fore.GREEN}Analyzing JavaScript files for sensitive data...{Style.RESET_ALL}")
        js_analysis = await analyze_js_files(js_files, args.quiet_js, use_wayback, timeout, max_file_size)

    logger.info(f"{Fore.GREEN}Saving results...{Style.RESET_ALL}")
    save_results(output_folder, domain, categorized_links, email_links, sensitive_links, js_analysis, links)
    logger.info(f"{Fore.GREEN}Process completed!{Style.RESET_ALL}")

if __name__ == "__main__":
    asyncio.run(main())