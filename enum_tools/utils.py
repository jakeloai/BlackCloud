"""
Helper functions for network requests, etc. Part of the cloud_enum package.
"""

import time
import sys
import datetime
import re
import csv
import json
import ipaddress
from multiprocessing.dummy import Pool as ThreadPool
from functools import partial
from urllib.parse import urlparse

try:
    import requests
    import dns
    import dns.resolver
    from concurrent.futures import ThreadPoolExecutor
    from requests_futures.sessions import FuturesSession
    from concurrent.futures._base import TimeoutError
except ImportError:
    print("[!] Please pip install requirements.txt.")
    sys.exit()

LOGFILE = False
LOGFILE_FMT = ''


def init_logfile(logfile, fmt):
    """
    Initialize the global logfile if specified as a user-supplied argument
    """
    if logfile:
        global LOGFILE
        LOGFILE = logfile

        global LOGFILE_FMT
        LOGFILE_FMT = fmt

        now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        with open(logfile, 'a', encoding='utf-8') as log_writer:
            log_writer.write(f"\n\n#### CLOUD_ENUM {now} ####\n")


def is_valid_domain(domain):
    """
    Checks if the domain has a valid format and length
    """
    if len(domain) > 253:  # According to DNS specifications
        return False

    for label in domain.split('.'):
        if not (1 <= len(label) <= 63):
            return False
        
    return True


def get_url_batch(url_list, use_ssl=False, callback='', threads=5, redir=True):
    """
    Processes a list of URLs, sending the results back to the calling
    function in real-time via the `callback` parameter
    """
    tick = {}
    tick['total'] = len(url_list)
    tick['current'] = 0

    url_list = [url for url in url_list if is_valid_domain(url)]
    queue = [url_list[x:x+threads] for x in range(0, len(url_list), threads)]

    if use_ssl:
        proto = 'https://'
    else:
        proto = 'http://'

    for batch in queue:
        session = FuturesSession(executor=ThreadPoolExecutor(max_workers=threads+5))
        batch_pending = {}
        batch_results = {}

        for url in batch:
            batch_pending[url] = session.get(proto + url, allow_redirects=redir, verify=False)

        for url in batch_pending:
            try:
                batch_results[url] = batch_pending[url].result(timeout=30)
            except requests.exceptions.SSLError:
                # Handle cases where SSL handshake fails but service exists
                pass
            except requests.exceptions.ConnectionError as error_msg:
                pass
            except TimeoutError:
                print(f"    [!] Timeout on {url}. Investigate if network congestion is high.")

        for url in batch_results:
            check = callback(batch_results[url])
            if check == 'breakout':
                return

        tick['current'] += len(batch)
        sys.stdout.flush()
        sys.stdout.write(f"    {tick['current']}/{tick['total']} complete...")
        sys.stdout.write('\r')

    sys.stdout.write('                                \r')


def read_nameservers(file_path):
    """
    Reads nameservers from a given file.
    """
    try:
        with open(file_path, 'r') as file:
            nameservers = [line.strip() for line in file if line.strip() and not line.startswith('#')]
        if not nameservers:
            raise ValueError("Nameserver file is empty or only contains comments")
        return nameservers
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        exit(1)
    except ValueError as e:
        print(e)
        exit(1)


def is_valid_ip(address):
    try:
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False


def dns_lookup(nameserver, name):
    """
    This function performs the actual DNS lookup when called in a threadpool
    """
    nameserverfile = False
    if not is_valid_ip(nameserver):
        nameserverfile = nameserver

    res = dns.resolver.Resolver()
    res.timeout = 3
    res.lifetime = 3
    
    if nameserverfile:
        nameservers = read_nameservers(nameserverfile)
        res.nameservers = nameservers
    else:
        res.nameservers = [nameserver]

    tries = 0
    while tries < 3:
        try:
            res.resolve(name)
            return name
        except dns.resolver.NXDOMAIN:
            return ''
        except dns.resolver.NoNameservers as exc_text:
            print("    [!] Error querying nameservers! This could be a problem.")
            print("    [!] If you're using a VPN, try setting --ns to your VPN's nameserver.")
            print("    [!] Bailing because you need to fix this")
            return '-#BREAKOUT_DNS_ERROR#-'
        except (dns.exception.Timeout, dns.resolver.NoAnswer):
            tries += 1

    return ''


def fast_dns_lookup(names, nameserver, nameserverfile, callback='', threads=5):
    """
    Helper function to resolve DNS names. Uses multithreading.
    """
    total = len(names)
    current = 0
    valid_names = []

    print(f"[*] Brute-forcing a list of {total} possible DNS names")

    names = [name for name in names if is_valid_domain(name)]
    queue = [names[x:x+threads] for x in range(0, len(names), threads)]

    for batch in queue:
        pool = ThreadPool(threads)

        if nameserverfile:
            dns_lookup_params = partial(dns_lookup, nameserverfile)
        else:
            dns_lookup_params = partial(dns_lookup, nameserver)

        results = pool.map(dns_lookup_params, batch)

        for name in results:
            if name:
                if name == '-#BREAKOUT_DNS_ERROR#-':
                    sys.exit()
                if callback:
                    callback(name)
                valid_names.append(name)

        current += len(batch)
        sys.stdout.flush()
        sys.stdout.write(f"    {current}/{total} complete...")
        sys.stdout.write('\r')
        pool.close()
        pool.join()

    sys.stdout.write('                                \r')
    return valid_names


def list_bucket_contents(bucket):
    """
    Provides a list of full URLs to each open bucket
    """
    key_regex = re.compile(r'<(?:Key|Name)>(.*?)</(?:Key|Name)>')
    try:
        reply = requests.get(bucket, verify=False, timeout=15)
        keys = re.findall(key_regex, reply.text)
    except requests.exceptions.RequestException:
        keys = []

    sub_regex = re.compile(r'(\?.*)')
    bucket = sub_regex.sub('', bucket)

    if keys:
        print("      FILES:")
        for key in keys:
            url = bucket + key
            print(f"      ->{url}")
    else:
        print("      ...empty bucket, so sad. :(")


def fmt_output(data):
    """
    Handles the output - printing and logging based on a specified format
    """
    bold = '\033[1m'
    end = '\033[0m'
    ansi = end
    
    if data['access'] == 'public':
        ansi = bold + '\033[92m'  # green
    elif data['access'] == 'protected':
        ansi = bold + '\033[33m'  # orange
    elif data['access'] == 'disabled':
        ansi = bold + '\033[31m'  # red

    sys.stdout.write('  ' + ansi + data['msg'] + ': ' + data['target'] + end + '\n')

    if LOGFILE:
        with open(LOGFILE, 'a', encoding='utf-8') as log_writer:
            if LOGFILE_FMT == 'text':
                log_writer.write(f'{data["msg"]}: {data["target"]}\n')
            elif LOGFILE_FMT == 'csv':
                writer = csv.DictWriter(log_writer, fieldnames=data.keys())
                writer.writerow(data)
            elif LOGFILE_FMT == 'json':
                log_writer.write(json.dumps(data) + '\n')


def get_brute(brute_file, mini=1, maxi=63, banned='[^a-z0-9_-]'):
    """
    Generates a list of brute-force words based on length and allowed chars
    """
    with open(brute_file, encoding="utf8", errors="ignore") as infile:
        names = infile.read().splitlines()

    banned_chars = re.compile(banned)
    clean_names = []
    for name in names:
        name = name.lower()
        name = banned_chars.sub('', name)
        if maxi >= len(name) >= mini:
            if name not in clean_names:
                clean_names.append(name)

    return clean_names


def start_timer():
    """
    Starts a timer for functions in main module
    """
    return time.time()


def stop_timer(start_time):
    """
    Stops timer and prints a status
    """
    elapsed_time = time.time() - start_time
    formatted_time = time.strftime("%H:%M:%S", time.gmtime(elapsed_time))

    print("")
    print(f" Elapsed time: {formatted_time}")
    print("")