# ReconVue — Operation Manual

## 1. Server Access

### 1.1 Connect to the VPS

| Item | Value |
|------|-------|
| IP address | `173.230.132.75` |
| Username | `root` |
| Password | `fatpigeatcorn13579@@` |

Use this command to connect:

```
ssh root@173.230.132.75
```

Type the password when the system asks for it.

### 1.2 Log in to ReconVue

Open your browser.  
Go to `http://173.230.132.75:8000`.  
The login page will show.

| Field | Value |
|-------|-------|
| Username | `killer_doddle` |
| Password | `Cremated123@` |

Type your username.  
Type your password.  
Click **Sign In**.

### 1.3 The PHP site (port 8001)

Another developer can use port 8001.  
Go to `http://173.230.132.75:8001`.  
The page shows the PHP site status.  
There is no login.  
The code is in `/opt/site2_php/public/`.  
To start the site manually:

```
cd /opt/site2_php
nohup php -S 0.0.0.0:8001 -t public/ > /tmp/php_clanker.log 2>&1 &
```

### 1.4 Database

PostgreSQL runs on `localhost:5432`.

| Database | Username | Password |
|----------|----------|----------|
| `reconvue` | `reconvue` | `reconvue123` |
| `clanker_db` | `clanker` | `clanker123` |

Redis runs on `localhost:6379`. There is no password.

---

## 2. Organisation Management

### 2.1 Create an Organisation

1. Click **Orgs** in the top menu.
2. Click **New Organisation**.
3. Type the organisation name.
4. Click **Create**.

### 2.2 Add a Domain to an Organisation

1. Open the organisation page.
2. Click **Add Domain**.
3. Type the domain (example: `selar.com`).
4. Click **Add**.

### 2.3 Start ASN Discovery

The ASN discovery finds IP ranges that belong to the organisation.

1. Open the organisation page.
2. Click **Start ASN Scan**.
3. Wait. The scan takes 1 to 5 hours for large organisations.
4. The live feed shows the progress.
5. When the scan completes, the page shows CIDR ranges and open IPs.

### 2.4 Delete an Organisation

1. Open the organisation page.
2. Click **Delete**.
3. Confirm the deletion.

---

## 3. Domain Scanning

### 3.1 Start a Scan

1. Click **Projects** in the top menu.
2. Find the domain you want to scan.
3. Click **Start Scan**.
4. The live scan page will show.

### 3.2 The Live Scan Page

The live scan page shows:
- A progress bar with the current step.
- Counters for subdomains, resolved hosts, live hosts, ports, findings, and secrets.
- A terminal-style log feed that updates every 1.5 seconds.

The scan has 8 steps:
1. Subdomain Enumeration — finds subdomains with subfinder, amass, shuffledns, altdns, and dnsx.
2. Port Scanning — scans open TCP ports with naabu (top-1000 first, then full 1-10000 in background).
3. HTTP Probing — checks live HTTP services with httpx.
4. Google Dorks — finds Google search links.
5. Link Gathering — collects URLs with katana and secrets with trufflehog.
6. Takeover Check — finds subdomain takeover risks with subjack.
7. S3 Bucket Scan — checks for open S3 buckets.
8. XSS Scanning — scans for cross-site scripting with dalfox.

After all steps complete, nuclei runs in the background on all open ports.

When the scan completes, a message will ask you to view the results.

### 3.3 Scan Results Page

Click **View Results** or open the scan from the project page.

The scan page has these tabs:

- **Overview** — summary counts and a pie chart of subdomain sources.
- **Subdomains** — every discovered subdomain with its IP address, HTTP status, title, and technologies. Click the arrow to expand and see sources.
- **Ports** — open TCP ports grouped by subdomain. Each row has a **Nuclei** button (see Section 4).
- **Findings** — nuclei vulnerability findings with severity, template name, and matched host.
- **Secrets** — leaked credentials or API keys found by trufflehog.
- **Endpoints** — API endpoints discovered by katana.
- **Takeover** — subdomains vulnerable to takeover.
- **S3** — open S3 buckets.
- **XSS** — XSS vulnerabilities.
- **Dorks** — Google dork search queries.
- **JS Files** — JavaScript files with a code viewer and keyword highlight.

### 3.4 Compare Two Scans (Diff)

1. Open a project page.
2. Click **Diff Scans**.
3. Select scan A and scan B.
4. Click **Compare**.
5. The page shows subdomains that are new, removed, or changed between the two scans.

### 3.5 Test DNS

1. Open a project page.
2. Click **Test DNS**.
3. The system runs shuffledns with a small wordlist sample.
4. The result shows if DNS resolution works for this domain.

---

## 4. Per-Subdomain Nuclei Scanning

### 4.1 Run Nuclei on a Single Subdomain

1. Open a scan page.
2. Click the **Ports** tab.
3. Find the subdomain row you want to scan.
4. Click the **Nuclei** button on that row.

The button will change to a spinner with "Running...".  
When the scan completes, the button shows the number of findings.

### 4.2 View the Live Nuclei Log

After you click **Nuclei**, a terminal icon will show next to the button.  
Click the terminal icon.  
A new tab opens with a live log page.  
The log page shows the nuclei scan output in real time.  
It updates every 2 seconds.

The log shows:
- The targets that nuclei will scan (largest port first).
- The nuclei banner and template loading.
- Progress messages from nuclei.
- The final number of findings.

When the scan completes, the page shows **DONE** and the finding count.

### 4.3 View Findings

1. Open the scan page.
2. Click the **Findings** tab.
3. Findings from all per-subdomain scans will show here.

Each finding shows:
- **Severity** — critical, high, medium, low, or info.
- **Template** — the nuclei template name.
- **Matched at** — the host and port where the finding was detected.

---

## 5. Port Scanning Detail

### 5.1 How Port Scanning Works

The port scan uses naabu.  
It scans the top 1000 TCP ports first.  
The results show in the scan immediately.  
A background process then scans all ports from 1 to 10000.  
When the background scan completes, it merges the results.

### 5.2 View Open Ports

1. Open a scan page.
2. Click the **Ports** tab.
3. Each row shows a subdomain and its open port numbers.
4. Badges show each port number.
5. Use the **Filter** box to find a specific subdomain.

### 5.3 Run Nuclei on Ports

See Section 4 for instructions.

---

## 6. Subdomain Discovery

### 6.1 Sources

Subdomains come from these sources:
- **subfinder** — passive DNS data from multiple APIs.
- **amass** — passive enumeration from certificate transparency and other sources.
- **shuffledns** — DNS brute-force with a 114,000 word wordlist.
- **altdns** — permutation discovery (admin, dev, staging, API, etc.).
- **dnsx** — DNS resolution to find IP addresses.
- **httpx** — HTTP probing to find live web services.

### 6.2 Skip Subfinder and Amass

To skip subfinder and amass during a scan:

1. SSH to the VPS.
2. Open the scan page on ReconVue.
3. Before you start the scan, run:

```
cd /opt/recon_web
source .venv/bin/activate
export RECON_SKIP_PASSIVE=true
```

4. Start the scan normally.
5. Subfinder and amass will not run. Only shuffledns and altdns will find subdomains.

To enable them again:

```
export RECON_SKIP_PASSIVE=
```

Or set the value to an empty string.

---

## 7. GitHub Workflow

### 7.1 Push Code Changes

All changes to ReconVue code go through GitHub.

The repository is: `git@github.com:lordseidon/recon-vps.git`

To push code:

```
cd /home/lordseidon/recon      # On your local machine
cd recon_web
git add -A
git commit -m "Description of the change"
git push origin master
```

### 7.2 Deploy to the VPS

After you push to GitHub:

```
ssh root@173.230.132.75
cd /opt/recon_web
git pull
rm -rf scanner/__pycache__/
```

The Django server will reload automatically.  
Restart the worker if you changed tasks:

```
pkill -f "celery.*worker"
cd /opt/recon_web
source .venv/bin/activate
export PYTHONPATH=/opt/recon_web
nohup .venv/bin/celery -A recon_web worker --loglevel=info --concurrency=2 > /tmp/celery.log 2>&1 &
```

---

## 8. Troubleshooting

### 8.1 Scan Status Is "Pending"

If a scan shows "pending" and does not start:

- Make sure the celery worker is running.
- Check the celery log: `tail -50 /tmp/celery.log`
- If the worker is not running, start it:

```
cd /opt/recon_web
source .venv/bin/activate
export PYTHONPATH=/opt/recon_web
nohup .venv/bin/celery -A recon_web worker --loglevel=info --concurrency=2 > /tmp/celery.log 2>&1 &
```

### 8.2 Scan Status Is Stuck on "Running"

If a scan does not make progress for more than 1 hour:

1. Kill the running processes:

```
pkill -f "recon.sh"
pkill -f "naabu"
pkill -f "nuclei"
```

2. Mark the scan as failed:

```
cd /opt/recon_web
source .venv/bin/activate
python3 -c "
import os,django
os.environ['DJANGO_SETTINGS_MODULE']='recon_web.settings'
import sys; sys.path.insert(0,'/opt/recon_web'); django.setup()
from scanner.models import Scan
s = Scan.objects.get(id=SCAN_ID)
s.status = 'failed'
s.error_message = 'Stuck — killed manually'
s.save()
"
```

3. Delete the scan and start a new one.

### 8.3 DNS Stack Issues

The DNS stack uses:
- **dnsdist** on port 53 — load balancer.
- **pdns-recursor** on ports 5301, 5302, 5303 — recursive resolvers.

Check if the DNS stack is working:

```
dig @127.0.0.1 google.com
```

To restart the DNS stack:

```
systemctl restart dnsdist
systemctl restart pdns-recursor@recursor1
systemctl restart pdns-recursor@recursor2
systemctl restart pdns-recursor@recursor3
```

### 8.4 ASN Scan Shows Wrong Org Data

If an organisation page shows data from another organisation:

1. SSH to the VPS.
2. Clear the scan logs:

```
cd /opt/recon_web
source .venv/bin/activate
python3 -c "
import os,django
os.environ['DJANGO_SETTINGS_MODULE']='recon_web.settings'
import sys; sys.path.insert(0,'/opt/recon_web'); django.setup()
from scanner.models import ScanLog
ScanLog.objects.filter(scan__isnull=True).delete()
print('Logs cleared')
"
```

3. The live feed now only shows logs for the current organisation.

### 8.5 Restart Django

If the web interface does not respond:

```
pkill -f "manage.py runserver"
cd /opt/recon_web
source .venv/bin/activate
export PYTHONPATH=/opt/recon_web
nohup .venv/bin/python manage.py runserver 0.0.0.0:8000 > /tmp/django.log 2>&1 &
```

---

## 9. Key Paths on the VPS

| Path | Purpose |
|------|---------|
| `/opt/recon_web/` | ReconVue Django project |
| `/opt/recon_web/scripts/` | Bash scripts (recon.sh, portscan.sh, nuclei.sh, asn_scan.sh, etc.) |
| `/opt/recon_web/scanner/` | Django app (models, views, tasks, templates) |
| `/opt/recon_web/outputs/` | Scan output files |
| `/opt/recon_web/outputs/<domain>/<date>/` | Per-scan output directory |
| `/opt/wordlists/` | Wordlists for DNS brute-force |
| `/opt/wordlists/subdomains.txt` | 114,000 word subdomain list |
| `/opt/wordlists/altdns-words.txt` | 224 word permutation list |
| `/root/go/bin/` | Go tools (nuclei, naabu, httpx, subfinder, amass, shuffledns, dnsx, katana, dalfox, subjack, trufflehog, gau, waybackurls, caduceus, asnmap) |
| `/root/resolvers.txt` | DNS resolver (127.0.0.1 — local dnsdist) |
| `/tmp/celery.log` | Celery worker log |
| `/tmp/django.log` | Django server log |
