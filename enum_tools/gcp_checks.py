"""
Google-specific checks. Part of the cloud_enum package available at
github.com/initstring/cloud_enum
"""

from enum_tools import utils
from enum_tools import gcp_regions

BANNER = '''
++++++++++++++++++++++++++
      google checks
++++++++++++++++++++++++++
'''

# Known GCP domain names
GCP_URL = 'storage.googleapis.com'
FBRTDB_URL = 'firebaseio.com'
APPSPOT_URL = 'appspot.com'
FUNC_URL = 'cloudfunctions.net'
FBAPP_URL = 'firebaseapp.com'

# --- 2026 Expanded Endpoints ---
# Cloud Run (Modern Serverless Container hosting)
# Format typical: [SERVICE_NAME]-[PROJECT_HASH]-[REGION_CODE].run.app
# Note: For standard external generic enumeration, brute-forcing names directly is often targeted.
RUN_URL = 'run.app'
# Artifact Registry (Modern Package / Container Registry replacement for GCR)
ARTIFACT_URL = 'pkg.dev'
# Legacy Container Registry
GCR_URL = 'gcr.io'
# GCP API Gateway
APIGW_URL = 'gateway.dev'

# Hacky, I know. Used to store project/region combos that report at least
# one cloud function, to brute force later on
HAS_FUNCS = []


def print_bucket_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        data['msg'] = 'OPEN GOOGLE BUCKET'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
        utils.list_bucket_contents(reply.url + '/')
    elif reply.status_code == 403:
        data['msg'] = 'Protected Google Bucket'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              f"       {reply.status_code}: {reply.reason}")


def check_gcp_buckets(names, threads):
    """
    Checks for open and restricted Google Cloud buckets
    """
    print("[+] Checking for Google buckets")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of correctly formatted urls
    candidates = []

    # Take each mutated keyword craft a url with the correct format
    for name in names:
        candidates.append(f'{GCP_URL}/{name}')

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(candidates, use_ssl=False,
                        callback=print_bucket_response,
                        threads=threads)

    # Stop the time
    utils.stop_timer(start_time)


def print_fbrtdb_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        data['msg'] = 'OPEN GOOGLE FIREBASE RTDB'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code == 401:
        data['msg'] = 'Protected Google Firebase RTDB'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 402:
        data['msg'] = 'Payment required on Google Firebase RTDB'
        data['target'] = reply.url
        data['access'] = 'disabled'
        utils.fmt_output(data)
    elif reply.status_code == 423:
        data['msg'] = 'The Firebase database has been deactivated.'
        data['target'] = reply.url
        data['access'] = 'disabled'
        utils.fmt_output(data)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              f"       {reply.status_code}: {reply.reason}")


def check_fbrtdb(names, threads):
    """
    Checks for Google Firebase RTDB
    """
    print("[+] Checking for Google Firebase Realtime Databases")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of correctly formatted urls
    candidates = []

    # Take each mutated keyword craft a url with the correct format
    for name in names:
        # Firebase RTDB names cannot include a period. We'll exlcude
        # those from the global candidates list
        if '.' not in name:
            candidates.append(f'{name}.{FBRTDB_URL}/.json')

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_fbrtdb_response,
                        threads=threads,
                        redir=False)

    # Stop the time
    utils.stop_timer(start_time)


def print_fbapp_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 200:
        data['msg'] = 'OPEN GOOGLE FIREBASE APP'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              f"       {reply.status_code}: {reply.reason}")


def check_fbapp(names, threads):
    """
    Checks for Google Firebase Applications
    """
    print("[+] Checking for Google Firebase Applications")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of correctly formatted urls
    candidates = []

    # Take each mutated keyword craft a url with the correct format
    for name in names:
        # Firebase App names cannot include a period. We'll exlcude
        # those from the global candidates list
        if '.' not in name:
            candidates.append(f'{name}.{FBAPP_URL}')

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(candidates, use_ssl=True,
                        callback=print_fbapp_response,
                        threads=threads,
                        redir=False)

    # Stop the time
    utils.stop_timer(start_time)


def print_appspot_response(reply):
    """
    Parses the HTTP reply of a brute-force attempt

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif str(reply.status_code)[0] == '5':
        data['msg'] = 'Google App Engine app with a 50x error'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code in (200, 302, 404):
        if 'accounts.google.com' in reply.url:
            data['msg'] = 'Protected Google App Engine app'
            data['target'] = reply.history[0].url
            data['access'] = 'protected'
            utils.fmt_output(data)
        else:
            data['msg'] = 'Open Google App Engine app'
            data['target'] = reply.url
            data['access'] = 'public'
            utils.fmt_output(data)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              f"       {reply.status_code}: {reply.reason}")


def check_appspot(names, threads):
    """
    Checks for Google App Engine sites running on appspot.com
    """
    print("[+] Checking for Google App Engine apps")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of correctly formatted urls
    candidates = []

    # Take each mutated keyword craft a url with the correct format
    for name in names:
        # App Engine project names cannot include a period. We'll exlcude
        # those from the global candidates list
        if '.' not in name:
            candidates.append(f'{name}.{APPSPOT_URL}')

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(candidates, use_ssl=False,
                        callback=print_appspot_response,
                        threads=threads)

    # Stop the time
    utils.stop_timer(start_time)


def print_functions_response1(reply):
    """
    Parses the HTTP reply the initial Cloud Functions check

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code == 302:
        data['msg'] = 'Contains at least 1 Cloud Function'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
        HAS_FUNCS.append(reply.url)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              f"       {reply.status_code}: {reply.reason}")


def print_functions_response2(reply):
    """
    Parses the HTTP reply from the secondary, brute-force Cloud Functions check

    This function is passed into the class object so we can view results
    in real-time.
    """
    data = {'platform': 'gcp', 'msg': '', 'target': '', 'access': ''}

    if 'accounts.google.com/ServiceLogin' in reply.url:
        pass
    elif reply.status_code in (403, 401):
        data['msg'] = 'Auth required Cloud Function'
        data['target'] = reply.url
        data['access'] = 'protected'
        utils.fmt_output(data)
    elif reply.status_code == 405:
        data['msg'] = 'UNAUTHENTICATED Cloud Function (POST-Only)'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code in (200, 404):
        data['msg'] = 'UNAUTHENTICATED Cloud Function (GET-OK)'
        data['target'] = reply.url
        data['access'] = 'public'
        utils.fmt_output(data)
    else:
        print(f"    Unknown status codes being received from {reply.url}:\n"
              f"       {reply.status_code}: {reply.reason}")


def check_functions(names, brute_list, quickscan, threads):
    """
    Checks for Google Cloud Functions running on cloudfunctions.net
    """
    print("[+] Checking for project/zones with Google Cloud Functions.")

    # Start a counter to report on elapsed time
    start_time = utils.start_timer()

    # Initialize the list of correctly formatted urls
    candidates = []

    # Pull the regions from a config file
    regions = gcp_regions.REGIONS

    print(f"[*] Testing across {len(regions)} regions defined in the config file")

    # Take each mutated keyword craft a url with the correct format
    for region in regions:
        candidates += [region + '-' + name + '.' + FUNC_URL for name in names]

    # Send the valid names to the batch HTTP processor
    utils.get_url_batch(candidates, use_ssl=False,
                        callback=print_functions_response1,
                        threads=threads,
                        redir=False)

    # Return from function if we have not found any valid combos
    if not HAS_FUNCS:
        utils.stop_timer(start_time)
        return

    # Also bail out if doing a quick scan
    if quickscan:
        return

    print(f"[*] Brute-forcing function names in {len(HAS_FUNCS)} project/region combos")

    # Load brute list in memory
    brute_strings = utils.get_brute(brute_list)

    for func in HAS_FUNCS:
        print(f"[*] Brute-forcing {len(brute_strings)} function names in {func}")
        func = func.replace("http://", "")
        candidates = [func + brute + '/' for brute in brute_strings]

        # Send the valid names to the batch HTTP processor
        utils.get_url_batch(candidates, use_ssl=False,
                            callback=print_functions_response2,
                            threads=threads)

    # Stop the time
    utils.stop_timer(start_time)


# --- 2026 New GCP Service Implementation Functions & Callbacks ---

def print_generic_gcp_response(reply, service_name):
    """
    Generic HTTP response parser callback for expanded GCP endpoints
    """
    data = {'platform': 'gcp', 'msg': '', 'target': reply.url, 'access': ''}

    if reply.status_code == 404:
        pass
    elif reply.status_code in (200, 302):
        if 'accounts.google.com' in reply.url:
            data['msg'] = f'Protected Google {service_name}'
            data['access'] = 'protected'
        else:
            data['msg'] = f'Open Google {service_name}'
            data['access'] = 'public'
        utils.fmt_output(data)
    elif reply.status_code in (401, 403):
        data['msg'] = f'Protected Google {service_name}'
        data['access'] = 'protected'
        utils.fmt_output(data)
    else:
        pass


def check_gcp_expanded_services(names, url_format_func, service_label, threads):
    """
    A generic orchestration layout to process batch URLs for newly introduced endpoints
    """
    print(f"[+] Checking for Google {service_label}")
    start_time = utils.start_timer()

    candidates = []
    for name in names:
        if '.' not in name:
            candidates.append(url_format_func(name))

    if candidates:
        utils.get_url_batch(candidates, use_ssl=True,
                            callback=lambda reply: print_generic_gcp_response(reply, service_label),
                            threads=threads)

    utils.stop_timer(start_time)


def run_all(names, args):
    """
    Function is called by main program
    """
    print(BANNER)

    # Baseline core checks
    check_gcp_buckets(names, args.threads)
    check_fbrtdb(names, args.threads)
    check_fbapp(names, args.threads)
    check_appspot(names, args.threads)
    check_functions(names, args.brute, args.quickscan, args.threads)

    # --- 2026 Expanded GCP Services Queue ---
    # Container / Package Registries
    check_gcp_expanded_services(names, lambda n: f'{GCR_URL}/{n}', "Legacy Container Registry Projects", args.threads)
    check_gcp_expanded_services(names, lambda n: f'https://us-docker.{ARTIFACT_URL}/{n}', "Artifact Registry US Repositories", args.threads)
    
    # API Gateways & Cloud Run Endpoints (uses generic base project formats)
    check_gcp_expanded_services(names, lambda n: f'{n}.{APIGW_URL}', "API Gateways", args.threads)
    check_gcp_expanded_services(names, lambda n: f'{n}.{RUN_URL}', "Cloud Run Base Service URLs", args.threads)