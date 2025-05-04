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

# Initialize colorama
init(autoreset=True)

# Setup logging
def setup_logging(verbose: bool) -> None:
    """Configure logging with simple or verbose format based on user input."""
    log_format = "%(message)s" if not verbose else "%(asctime)s [%(levelname)s] %(message)s"
    logging.basicConfig(
        level=logging.INFO,
        format=log_format,
        handlers=[logging.StreamHandler()]
    )

# Initialize cache
cache = cachetools.TTLCache(maxsize=100, ttl=3600)  # Cache for 1 hour

async def fetch_wayback_links(domain: str, retries: int = 3, timeout: int = 60) -> list[str]:
    """Fetch unique URLs from Wayback Machine for a given domain with retry mechanism."""
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
                        logger.info(f"{Fore.GREEN}Fetched {len(links)} unique links for {domain}{Style.RESET_ALL}")
                        return links
                    else:
                        logger.error(f"{Fore.RED}Failed to fetch links for {domain}: HTTP {response.status}{Style.RESET_ALL}")
                        return []
        except aiohttp.ClientError as e:
            logger.error(f"{Fore.RED}Attempt {attempt + 1}/{retries} - Network error while fetching links for {domain}: {e}{Style.RESET_ALL}")
            if attempt == retries - 1:  # Last attempt
                logger.error(f"{Fore.RED}All attempts failed. Check your internet connection or try again later.{Style.RESET_ALL}")
                return []
            await asyncio.sleep(2 ** attempt)  # Exponential backoff: 1s, 2s, 4s
        except asyncio.TimeoutError:
            logger.error(f"{Fore.RED}Attempt {attempt + 1}/{retries} - Timeout while fetching links for {domain}. The server may be slow.{Style.RESET_ALL}")
            if attempt == retries - 1:  # Last attempt
                logger.error(f"{Fore.RED}All attempts failed due to timeout. Consider increasing the timeout or checking your connection.{Style.RESET_ALL}")
                return []
            await asyncio.sleep(2 ** attempt)  # Exponential backoff

def categorize_links(links: list[str]) -> tuple[defaultdict, list[str], list[str], list[str]]:
    """Categorize URLs based on file extensions, emails, and sensitive keywords."""
    file_extensions = re.compile(
        r'.*\.(js|xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|git|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|apk|msi|env|dmg|tmp|crt|pem|key|pub|asc)$',
        re.IGNORECASE
    )
    email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}')
    sensitive_pattern = re.compile(
        r'(api_key|secret|token|password|private|confidential|ssn|credit_card|auth|key|access_token|client_secret|username|email|oauth|bearer|jwt|'
        r'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|'
        r'AZIA[0-9A-Z]{16}|'
        r'AUZA[0-9A-Z]{16}|'
        r'AIza[0-9A-Za-z\-_]{35}|'
        r'4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})',  # Fixed closing parenthesis
        re.IGNORECASE
    )
    categorized = defaultdict(list)
    email_links = []
    sensitive_links = []
    js_files = []

    for link in links:
        if email_pattern.search(link):
            email_links.append(link)
        if sensitive_pattern.search(link):
            sensitive_links.append(link)
        match = file_extensions.search(link)
        if match:
            ext = match.group(1).lower()
            categorized[ext].append(link)
            if ext == "js":
                js_files.append(link)

    logger.info(f"{Fore.GREEN}Categorized {len(links)} links: {len(email_links)} emails, {len(sensitive_links)} sensitive, {len(js_files)} JS files{Style.RESET_ALL}")
    return categorized, email_links, sensitive_links, js_files

async def analyze_js_files(js_links: list[str], quiet_js: bool) -> list[tuple[str, set[str]]]:
    """Analyze JavaScript files for sensitive data."""
    sensitive_pattern = re.compile(
        r'(api_key|secret|token|password|private|confidential|ssn|credit_card|auth|key|access_token|client_secret|username|email|oauth|bearer|jwt|'
        r'AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|'
        r'AZIA[0-9A-Z]{16}|'
        r'AUZA[0-9A-Z]{16}|'
        r'AIza[0-9A-Za-z\-_]{35}|'
        r'4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})',  # Fixed closing parenthesis
        re.IGNORECASE
    )
    results = []

    async def fetch_js(url: str, session: aiohttp.ClientSession) -> tuple[str, set[str]] | None:
        try:
            async with session.get(url, timeout=10) as response:
                if response.status == 200:
                    text = await response.text()
                    matches = sensitive_pattern.findall(text)
                    if matches:
                        if not quiet_js:
                            logger.info(f"{Fore.MAGENTA}Found sensitive data in {url}: {matches}{Style.RESET_ALL}")
                        return url, set(matches)
                return None
        except aiohttp.ClientError as e:
            logger.warning(f"{Fore.YELLOW}Failed to analyze {url}: {e}{Style.RESET_ALL}")
            return None

    connector = aiohttp.TCPConnector(limit=50)  # Limit concurrent connections
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fetch_js(url, session) for url in js_links]
        responses = await asyncio.gather(*tasks, return_exceptions=True)
        for res in responses:
            if res and not isinstance(res, Exception):
                results.append(res)

    logger.info(f"{Fore.GREEN}Analyzed {len(js_links)} JS files, found sensitive data in {len(results)} files{Style.RESET_ALL}")
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
    sensitive_links: list[str],
    js_analysis: list[tuple[str, set[str]]],
    all_links: list[str]
) -> None:
    """Save categorized links and analysis results to files."""
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
        with open(f"{output_folder}/{domain_filename}-sensitive.txt", "w", encoding="utf-8") as file:
            file.write("\n".join(sensitive_links))
        logger.info(f"{Fore.RED}Saved sensitive links to {output_folder}/{domain_filename}-sensitive.txt{Style.RESET_ALL}")

    if js_analysis:
        with open(f"{output_folder}/{domain_filename}-js-analysis.txt", "w", encoding="utf-8") as file:
            for url, matches in js_analysis:
                file.write(f"{url} -> {', '.join(matches)}\n")
        logger.info(f"{Fore.MAGENTA}Saved JS analysis to {output_folder}/{domain_filename}-js-analysis.txt{Style.RESET_ALL}")

async def main() -> None:
    """Main function to orchestrate the OSINT tool workflow."""
    parser = argparse.ArgumentParser(description="oldRASHED - OSINT TOOL for extracting URLs from Wayback Machine. Use -h to see this help message and exit.")
    parser.add_argument("-u", "--url", required=True, help="Target domain (example.com)")
    parser.add_argument("-a", "--analyze-js", action="store_true", help="Enable JavaScript file analysis")
    parser.add_argument("-o", "--output", default="output", help="Output directory (default: output)")
    parser.add_argument("--cache", action="store_true", help="Enable caching of fetched links")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging with timestamps")
    parser.add_argument("--quiet-js", action="store_true", help="Suppress JS analysis output in CLI (results still saved to file)")

    args = parser.parse_args()
    domain = args.url
    output_folder = args.output

    setup_logging(args.verbose)
    global logger
    logger = logging.getLogger(__name__)

    logo = pyfiglet.figlet_format("oldRASHED")
    logger.info(f"{Fore.RED}{logo}{Style.RESET_ALL}")
    logger.info(f"{Fore.CYAN}OSINT TOOL - Wayback Machine Scraper{Style.RESET_ALL}")

    if not validators.domain(domain) and not validators.url(domain):
        logger.error(f"{Fore.RED}Invalid domain or URL: {domain}{Style.RESET_ALL}")
        return

    logger.info(f"{Fore.GREEN}Starting data collection for {domain}{Style.RESET_ALL}")
    links = await fetch_wayback_links(domain)
    if not links:
        logger.warning(f"{Fore.YELLOW}No links found!{Style.RESET_ALL}")
        return

    logger.info(f"{Fore.GREEN}Categorizing links...{Style.RESET_ALL}")
    categorized_links, email_links, sensitive_links, js_files = categorize_links(links)

    js_analysis = []
    if args.analyze_js and js_files:
        logger.info(f"{Fore.GREEN}Analyzing JavaScript files for sensitive data...{Style.RESET_ALL}")
        js_analysis = await analyze_js_files(js_files, args.quiet_js)

    logger.info(f"{Fore.GREEN}Saving results...{Style.RESET_ALL}")
    save_results(output_folder, domain, categorized_links, email_links, sensitive_links, js_analysis, links)
    logger.info(f"{Fore.GREEN}Process completed!{Style.RESET_ALL}")

if __name__ == "__main__":
    asyncio.run(main())