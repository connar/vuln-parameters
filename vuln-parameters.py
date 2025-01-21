import argparse
import requests
import re
import subprocess
from fake_useragent import UserAgent
import urllib3
from pwn import log
from urllib.parse import urlparse, parse_qs
from collections import Counter
from tabulate import tabulate
from termcolor import colored

urllib3.disable_warnings()

def extract_vuln_params(url, vuln_params):
    parsed_url = urlparse(url)
    query_params = parse_qs(parsed_url.query)

    return [param for param in query_params.keys() if param in vuln_params]

class CustomArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage()
        print(f"\nPlease provide a domain using the --domain argument.\nUse --help for more information.")
        self.exit(2)

def parse_args():
    parser = CustomArgumentParser(description="Download files until a certain size limit is reached.")
    parser.add_argument('--domain', type=str, help="Domain to analyze (e.g., example.com)")
    parser.add_argument('--size', type=int, help="Size to download in MB")
    args = parser.parse_args()

    if not args.domain:
        parser.error("Missing required argument: --domain")

    return args

def main():
    args = parse_args()
    domain = args.domain
    size_limit_mb = args.size if args.size else None

    vuln_params = set([
        'file', 'document', 'folder', 'root', 'path', 'pg', 'style', 'pdf', 'template', 'php_path', 
        'doc', 'page', 'name', 'cat', 'dir', 'action', 'board', 'date', 'detail', 'download', 'prefix', 
        'include', 'inc', 'locate', 'show', 'site', 'type', 'view', 'content', 'layout', 'mod', 'conf', 
        'daemon', 'upload', 'log', 'ip', 'cli', 'cmd', 'exec', 'command', 'execute', 'ping', 'query', 
        'jump', 'code', 'reg', 'do', 'func', 'arg', 'option', 'load', 'process', 'step', 'read', 'function', 
        'req', 'feature', 'exe', 'module', 'payload', 'run', 'print', 'callback', 'checkout', 'checkout_url', 
        'continue', 'data', 'dest', 'destination', 'domain', 'feed', 'file_name', 'file_url', 'folder_url', 
        'forward', 'from_url', 'go', 'goto', 'host', 'html', 'image_url', 'img_url', 'load_file', 'load_url', 
        'login_url', 'logout', 'navigation', 'next', 'next_page', 'Open', 'out', 'page_url', 'port', 'redir', 
        'redirect', 'redirect_to', 'redirect_uri', 'redirect_url', 'reference', 'return', 'return_path', 
        'return_to', 'returnTo', 'return_url', 'rt', 'rurl', 'target', 'to', 'uri', 'url', 'val', 'validate', 
        'window', 'q', 's', 'search', 'lang', 'keyword', 'keywords', 'year', 'email', 'p', 'jsonp', 'api_key', 
        'api', 'password', 'emailto', 'token', 'username', 'csrf_token', 'unsubscribe_token', 'id', 'item', 
        'page_id', 'month', 'immagine', 'list_type', 'terms', 'categoryid', 'key', 'l', 'begindate', 'enddate', 
        'select', 'report', 'role', 'update', 'user', 'sort', 'where', 'params', 'row', 'table', 'from', 'sel', 
        'results', 'sleep', 'fetch', 'order', 'column', 'field', 'delete', 'string', 'number', 'filter', 'access', 
        'admin', 'dbg', 'debug', 'edit', 'grant', 'test', 'alter', 'clone', 'create', 'disable', 'enable', 'make', 
        'modify', 'rename', 'reset', 'shell', 'toggle', 'adm', 'cfg', 'open', 'img', 'filename', 'preview', 'activity'
    ])

    ua = UserAgent()
    headers = {"user-agent": ua.chrome}

    wburl = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&collapse=urlkey&output=text&fl=original"

    print(f"Fetching URLs for *.{domain}/* ...")
    response_logger = log.progress("Downloading URLs")
    size_logger = log.progress("Data downloaded")

    try:
        response = requests.get(wburl, headers=headers, stream=True, verify=False)

        if response.status_code != 200:
            response_logger.failure(f"Failed to fetch URLs. HTTP Status Code: {response.status_code}")
            return

        raw_urls = []
        total_size = 0

        size_limit_bytes = size_limit_mb * 1024 if size_limit_mb else None

        for chunk in response.iter_content(chunk_size=1024):
            total_size += len(chunk)
            if size_limit_bytes and total_size > size_limit_bytes:
                break
            size_logger.status(f"{total_size} bytes downloaded / {size_limit_bytes if size_limit_bytes else 'N/A'} bytes")
            raw_urls.append(chunk.decode("utf-8", errors="ignore"))

        raw_urls = "".join(raw_urls)
        response_logger.success("URLs fetched successfully")
        size_logger.success(f"Total downloaded: {total_size} bytes")

        if size_limit_mb and total_size >= size_limit_bytes:
            size_logger.success(f"Download limit of {size_limit_mb} MB reached.")

    except Exception as e:
        response_logger.failure(f"Error occurred: {e}")
        return

    print("Running uro to deduplicate and clean URLs...")
    url_logger = log.progress("Processing URLs with uro")

    try:
        process = subprocess.Popen(
            ["uro"], 
            stdin=subprocess.PIPE, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )
        deduplicated_urls, errors = process.communicate(input=raw_urls)

        if process.returncode != 0:
            url_logger.failure(f"uro command failed with error: {errors}")
            return

        deduplicated_urls = list(set(deduplicated_urls.splitlines()))
        deduplicated_urls = [url for url in deduplicated_urls if url.strip()]
        url_logger.success(f"Processed {len(deduplicated_urls)} unique URLs")
    except Exception as e:
        url_logger.failure(f"Error running uro: {e}")
        return

    vulnerable_urls = []
    param_counter = Counter()

    for url in deduplicated_urls:
        vuln_params_in_url = extract_vuln_params(url, vuln_params)
        if vuln_params_in_url:
            vulnerable_urls.append(url)
            param_counter.update(vuln_params_in_url)

    table_data = []
    for param, count in param_counter.items():
        color = 'green' if count > 0 else 'red'
        table_data.append([colored(param, color), count])

    print("\nParameter Occurrences in URLs with Vulnerabilities:")
    print(tabulate(table_data, headers=["Vulnerable Parameter", "Occurrences"], tablefmt="grid"))

    output_file = "vuln_param_urls.txt"
    with open(output_file, "w") as f:
        f.write("\n".join(vulnerable_urls))

    print(f"Vulnerable URLs saved to {output_file}.")

if __name__ == "__main__":
    main()
