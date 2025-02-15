#!/usr/bin/env python3
import os
import aiohttp
import asyncio
import requests
import re
import argparse
import concurrent.futures
from collections import defaultdict
from colorama import Fore, Style, init
import pyfiglet

init(autoreset=True)

# Logo
logo = pyfiglet.figlet_format("oldRASHED")
print(Fore.RED + logo + Style.RESET_ALL)
print(Fore.CYAN + "        OSINT TOOL - Wayback Machine Scraper\n" + Style.RESET_ALL)


async def fetch_wayback_links(domain):
    url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&collapse=urlkey&output=text&fl=original"
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as response:
            if response.status == 200:
                text = await response.text()
                return list(set(text.splitlines()))
    return []

def categorize_links(links):
    file_extensions = re.compile(r'.*\.(js|xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|git|config|csv|yaml|md|md5|exe|dll|bin|ini|bat|sh|tar|deb|rpm|iso|img|apk|msi|env|dmg|tmp|crt|pem|key|pub|asc)$', re.IGNORECASE)  
    email_pattern = re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}') 
    sensitive_pattern = re.compile(r'(api_key|secret|token|password|private|confidential|ssn|credit_card|auth|key|access_token|client_secret)', re.IGNORECASE)
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

    return categorized, email_links, sensitive_links, js_files


async def analyze_js(js_links):
    sensitive_pattern = re.compile(r'(api_key|secret|token|password|private|confidential|ssn|credit_card|auth|key|access_token|client_secret)', re.IGNORECASE)
    results = []

    async def fetch_js(url, session):
        try:
            async with session.get(url, timeout=10) as response:
                if response.status == 200:
                    text = await response.text()
                    matches = sensitive_pattern.findall(text)
                    if matches:
                        return url, set(matches)
        except Exception:
            return None
        return None

    async with aiohttp.ClientSession() as session:
        tasks = [fetch_js(url, session) for url in js_links]
        responses = await asyncio.gather(*tasks)
        for res in responses:
            if res:
                results.append(res)
    return results

def save_links(output_folder, domain, categorized_links, email_links, sensitive_links, js_analysis, all_links):
    os.makedirs(output_folder, exist_ok=True)
    domain_filename = domain.replace("https://", "").replace("http://", "").replace("www.", "")

    with open(f"{output_folder}/{domain_filename}-all-links.txt", "w", encoding="utf-8") as file:
        file.write("\n".join(sorted(set(all_links))))
    print(Fore.BLUE + f"Saved: {output_folder}/{domain_filename}-all-links.txt" + Style.RESET_ALL)

    for ext, links in categorized_links.items():
        filename = f"{output_folder}/{domain_filename}-{ext}.txt"
        with open(filename, "w", encoding="utf-8") as file:
            file.write("\n".join(links))
        print(Fore.CYAN + f"Saved: {filename}" + Style.RESET_ALL)

    if email_links:
        with open(f"{output_folder}/{domain_filename}-emails.txt", "w", encoding="utf-8") as file:
            file.write("\n".join(email_links))
        print(Fore.YELLOW + f"Saved: {output_folder}/{domain_filename}-emails.txt" + Style.RESET_ALL)

    if sensitive_links:
        with open(f"{output_folder}/{domain_filename}-sensitive.txt", "w", encoding="utf-8") as file:
            file.write("\n".join(sensitive_links))
        print(Fore.RED + f"Saved: {output_folder}/{domain_filename}-sensitive.txt" + Style.RESET_ALL)

    if js_analysis:
        with open(f"{output_folder}/{domain_filename}-js-analysis.txt", "w", encoding="utf-8") as file:
            for url, matches in js_analysis:
                file.write(f"{url} -> {', '.join(matches)}\n")
        print(Fore.MAGENTA + f"Saved: {output_folder}/{domain_filename}-js-analysis.txt" + Style.RESET_ALL)

async def main():
    parser = argparse.ArgumentParser(description="oldRASHED - OSINT TOOL for extracting URLs from Wayback Machine")
    parser.add_argument("-u", "--url", required=True, help="Target domain (example.com)")
    parser.add_argument("-a", "--analyze-js", action="store_true", help="Enable JavaScript file analysis")
    parser.add_argument("-o", "--output", default="output", help="Output directory (default: output)")

    args = parser.parse_args()
    domain = args.url
    output_folder = args.output

    print(Fore.GREEN + f"Fetching data for {domain} from Wayback Machine..." + Style.RESET_ALL)
    links = await fetch_wayback_links(domain)
    if not links:
        print(Fore.RED + "No links found!" + Style.RESET_ALL)
        return

    print(Fore.GREEN + "Categorizing links..." + Style.RESET_ALL)
    categorized_links, email_links, sensitive_links, js_files = categorize_links(links)

    js_analysis = []
    if args.analyze_js and js_files:
        print(Fore.GREEN + "Analyzing JavaScript files for sensitive data..." + Style.RESET_ALL)
        js_analysis = await analyze_js(js_files)

    print(Fore.GREEN + "Saving results..." + Style.RESET_ALL)
    save_links(output_folder, domain, categorized_links, email_links, sensitive_links, js_analysis, links)
    print(Fore.GREEN + "Process completed!" + Style.RESET_ALL)

if __name__ == "__main__":
    asyncio.run(main())
