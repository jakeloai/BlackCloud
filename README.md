# BlackCloud

Multi-cloud OSINT tool designed to enumerate public resources and storage buckets in AWS, Azure, and Google Cloud.

Part of the BlackSecurity suite.

BlackCloud is an overhauled and modernized fork originally derived from the open-source tool cloud_enum by initstring. This version has been fully updated to support the 2026 latest cloud domains and service URLs, significantly expanding your attack surface enumeration capabilities while keeping the rock-solid core features intact.

---

## Key Features (Updated for 2026)

BlackCloud brute-forces and validates public-facing assets across the big three providers using highly efficient asynchronous HTTP and DNS requests:

* **Amazon Web Services (AWS):**
* Open / Protected S3 Buckets
* AWS Apps (WorkMail, WorkDocs, Connect, etc.)
* Cognito User Pools
* Elastic Beanstalk Environments
* API Gateways & AppSync GraphQL APIs


* **Microsoft Azure:**
* Storage Accounts & Open Blob Containers
* Hosted Databases, Virtual Machines, and Web Apps


* **Google Cloud Platform (GCP):**
* Open / Protected GCP Buckets
* Firebase Realtime Databases & Google App Engine sites
* Cloud Functions (Project/Region brute-forcing)
* Legacy Container Registries & Artifact Registry Repositories
* API Gateways & Cloud Run Base Service URLs



---

## Installation

BlackCloud utilizes modern Python packaging standards (pyproject.toml). It will automatically handle dependencies and register the command-line tool for you.

```bash
# 1. Clone the repository
git clone <YOUR_GITHUB_REPOSITORY_URL>

# 2. Navigate into the directory
cd blackcloud

# 3. Install the package and its dependencies cleanly
pip install .

```

---

## Usage

After installation, you can directly run the tool from anywhere, or use the execution script in the folder. To view all available command-line flags and parameters, run:

```bash
python blackcloud.py -h

```

### Quick Examples

**Basic keyword lookup:**

```bash
python blackcloud.py -k targetcompany

```

**Using multiple keywords and multi-threading (10 threads):**

```bash
python blackcloud.py -k targetcompany -k targetassets -t 10

```

**Using a bulk keyword file:**

```bash
python blackcloud.py -kf keywords.txt

```

**Quick scan (Disables second-level mutations for a faster pass):**

```bash
python blackcloud.py -k targetcompany -qs

```

---

## Core Options

| Flag | Long Option | Description |
| --- | --- | --- |
| `-h` | `--help` | Show the help menu and exit. |
| `-k` | `--keyword` | Keyword to probe. Can be specified multiple times. |
| `-kf` | `--keyfile` | Input text file containing a single keyword per line. |
| `-m` | `--mutations` | Path to a custom mutations fuzz list. |
| `-t` | `--threads` | Threads for HTTP brute-force (Default: 5). |
| `-ns` | `--nameserver` | Nameserver IP to use for sub-domain brute-forcing. |
| `-l` | `--logfile` | Path to append discovered items. |
| `-f` | `--format` | Log file format: text, json, or csv (Default: text). |
|  | `--disable-aws` | Skip all Amazon Web Services checks. |
|  | `--disable-azure` | Skip all Microsoft Azure checks. |
|  | `--disable-gcp` | Skip all Google Cloud Platform checks. |

---

## Disclaimer

This tool is strictly intended for authorized security audits, defensive asset discovery, and educational purposes. Do not use BlackCloud against targets without explicit prior written consent. The developers assume no liability for misuse or damage caused by this program.
