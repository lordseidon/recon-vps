# ReconVue — API Operation Manual

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

### 1.2 Base API URL

```
http://173.230.132.75:8000/api/
```

### 1.3 Authentication

All API endpoints need a session cookie.  
Send a POST request to get the cookie.

```
curl -c /tmp/cookies.txt \
  -X POST http://173.230.132.75:8000/login/ \
  -d "username=killer_doddle&password=Cremated123@"
```

Use the cookie for all other requests.

```
curl -b /tmp/cookies.txt \
  http://173.230.132.75:8000/api/projects/
```

### 1.4 Database

PostgreSQL runs on `localhost:5432`.

| Database | Username | Password |
|----------|----------|----------|
| `reconvue` | `reconvue` | `reconvue123` |

Redis runs on `localhost:6379`. There is no password.

---

## 2. Organisations

### 2.1 Create an Organisation

```
POST /api/organisations/

{
    "name": "ExampleCorp"
}
```

**Response:**
```json
{
    "id": 10,
    "name": "ExampleCorp",
    "slug": "examplecorp",
    "asn_status": "idle",
    "asn_cidr_count": 0,
    "asn_ip_count": 0,
    "asn_domain_count": 0
}
```

### 2.2 List All Organisations

```
GET /api/organisations/
```

### 2.3 Get One Organisation

```
GET /api/organisations/{id}/
```

### 2.4 Start ASN Discovery

```
POST /api/organisations/{id}/asn_scan/
```

**Response:**
```json
{"status": "started"}
```

If a scan is already running:
```json
{"error": "ASN scan already running"}
```
HTTP status: 409

### 2.5 Check ASN Status

Poll `GET /api/organisations/{id}/` and examine these fields:

| Field | Type | Meaning |
|-------|------|---------|
| `asn_status` | string | `"idle"`, `"running"`, or `"completed"` |
| `asn_cidr_count` | integer | Number of CIDR ranges found |
| `asn_ip_count` | integer | Number of open IP addresses |
| `asn_domain_count` | integer | Number of domains found from reverse DNS |

### 2.6 Delete an Organisation

```
DELETE /api/organisations/{id}/
```

---

## 3. Projects (Domains)

### 3.1 Create a Project

```
POST /api/projects/

{
    "name": "example.com",
    "domain": "example.com",
    "organisation": 10
}
```

The `organisation` field is the ID from Section 2.1. Use `null` if there is no organisation.

### 3.2 List All Projects

```
GET /api/projects/
```

### 3.3 Start a Domain Scan

```
POST /api/projects/{id}/scan/
```

**Response (success):**
```json
{
    "id": 41,
    "status": "pending",
    "scan_date": "2026-07-10",
    "project_domain": "example.com"
}
```

**Response if a scan already exists today:**
```json
{"error": "Scan for today already exists", "scan_id": 40}
```
HTTP status: 409

Only one scan per project per day is permitted.  
Delete the existing scan first if you must rescan.

### 3.4 List Scans for a Project

```
GET /api/scans/?project={project_id}
```

### 3.5 Get Scan Details

```
GET /api/scans/{scan_id}/
```

Key fields:
| Field | Meaning |
|-------|---------|
| `status` | `"pending"`, `"running"`, `"completed"`, `"failed"` |
| `subdomain_count` | Total subdomains found |
| `resolved_count` | Subdomains with DNS A/AAAA records |
| `live_count` | Subdomains with a live HTTP service |
| `port_count` | Total open TCP ports found |
| `nuclei_finding_count` | Total nuclei vulnerability findings |
| `secret_count` | Secrets found by trufflehog |
| `api_endpoint_count` | API endpoints found by katana |
| `takeover_count` | Subdomain takeover risks |
| `s3_bucket_count` | Open S3 buckets |
| `xss_finding_count` | XSS vulnerabilities |
| `completed_at` | Timestamp when the scan finished |

### 3.6 Get Scan Status (lightweight)

```
GET /api/scans/{scan_id}/status/
```

Returns the same data as `GET /api/scans/{scan_id}/` but faster.

### 3.7 Delete a Scan

```
DELETE /api/scans/{scan_id}/
```

---

## 4. Subdomains

### 4.1 Get Subdomains for a Scan

```
GET /api/scans/{scan_id}/subdomains/
```

**Response:**
```json
[
    {
        "id": 1700,
        "name": "mail.example.com",
        "ip": "192.0.2.50",
        "record_type": "A",
        "resolved": true,
        "http_url": "https://mail.example.com",
        "http_status": 200,
        "http_title": "Webmail Login",
        "technologies": ["Nginx", "PHP", "jQuery"],
        "sources": ["subfinder", "amass", "shuffledns"],
        "ports": [25, 80, 443, 587]
    }
]
```

### 4.2 All Subdomains (cross-scan)

```
GET /api/subdomains/
```

---

## 5. Ports

### 5.1 Get Ports for a Scan

```
GET /api/scans/{scan_id}/ports/
```

**Response:**
```json
[
    {
        "id": 5001,
        "subdomain": 1700,
        "subdomain_name": "mail.example.com",
        "port_number": 443,
        "protocol": "tcp",
        "service": ""
    }
]
```

### 5.2 All Ports (cross-scan)

```
GET /api/ports/
```

---

## 6. Nuclei Findings

### 6.1 Get All Findings for a Scan

```
GET /api/scans/{scan_id}/nuclei/
```

**Response:**
```json
[
    {
        "id": 100,
        "template_id": "springboot-heapdump",
        "name": "Spring Boot Actuator - Heap Dump Detection",
        "severity": "critical",
        "matched_at": "selfcare.example.com:8082",
        "host": "selfcare.example.com",
        "ip": "197.255.164.18",
        "extracted_results": "",
        "curl_command": ""
    }
]
```

### 6.2 Run Nuclei on One Subdomain

```
POST /api/scans/{scan_id}/nuclei-sub/{subdomain_id}/
```

**Response:**
```json
{
    "status": "started",
    "subdomain": "selfcare.example.com",
    "targets": 12
}
```

The task scans all open ports on that subdomain.  
It runs asynchronously. Poll for results.

### 6.3 Check Per-Subdomain Nuclei Status

```
GET /api/scans/{scan_id}/nuclei-sub/{subdomain_id}/status/
```

**Response:**
```json
{
    "running": false,
    "findings": 27,
    "subdomain": "selfcare.example.com",
    "logs": [
        {"msg": "Nuclei on selfcare.example.com: 12 targets", "cat": "nuclei_start", "id": 52001},
        {"msg": "Nuclei on selfcare.example.com done: 27 findings", "cat": "nuclei_done", "id": 52050}
    ]
}
```

Use `?since={log_id}` to get only new log entries.

```
GET /api/scans/{scan_id}/nuclei-sub/{subdomain_id}/status/?since=52001
```

### 6.4 All Nuclei Findings (cross-scan)

```
GET /api/nuclei/
```

---

## 7. Secrets

### 7.1 Get Secrets for a Scan

```
GET /api/scans/{scan_id}/secrets/
```

### 7.2 Toggle Verified Status

```
POST /api/scan/{secret_id}/toggle-verify/
```

---

## 8. Endpoints

### 8.1 Get API Endpoints for a Scan

```
GET /api/scans/{scan_id}/endpoints/
```

---

## 9. Takeover Checks

### 9.1 Get Takeover Results

```
GET /api/scans/{scan_id}/takeover/
```

---

## 10. S3 Buckets

### 10.1 Get S3 Bucket Results

```
GET /api/scans/{scan_id}/s3/
```

---

## 11. XSS Findings

### 11.1 Get XSS Findings

```
GET /api/scans/{scan_id}/xss/
```

---

## 12. Google Dorks

### 12.1 Get Dork Results

```
GET /api/scans/{scan_id}/dorks/
```

---

## 13. Compare Scans (Diff)

### 13.1 Get Diff Between Two Scans

```
GET /api/projects/{project_id}/diff/?scan_a={id}&scan_b={id}
```

---

## 14. ASN CIDR Ranges

### 14.1 Get CIDR Data

The organisation endpoint `GET /api/organisations/{id}/` includes CIDR data.  
There is no separate CIDR endpoint.  
CIDRs are stored as `ASNCIDR` objects and linked to the organisation.

---

## 15. Complete Workflow Example

### 15.1 Scan a Domain End to End

```bash
# 1. Log in
curl -c /tmp/cookies.txt \
  -X POST http://173.230.132.75:8000/login/ \
  -d "username=killer_doddle&password=Cremated123@"

# 2. Create an organisation
curl -b /tmp/cookies.txt \
  -X POST http://173.230.132.75:8000/api/organisations/ \
  -H "Content-Type: application/json" \
  -d '{"name":"ExampleCorp"}'

# Response: {"id":10, ...}

# 3. Create a project linked to the org
curl -b /tmp/cookies.txt \
  -X POST http://173.230.132.75:8000/api/projects/ \
  -H "Content-Type: application/json" \
  -d '{"name":"example.com","domain":"example.com","organisation":10}'

# Response: {"id":22, ...}

# 4. Start the domain scan
curl -b /tmp/cookies.txt \
  -X POST http://173.230.132.75:8000/api/projects/22/scan/

# Response: {"id":41, "status":"pending", ...}

# 5. Poll scan status until completed
while true; do
  STATUS=$(curl -b /tmp/cookies.txt -s \
    http://173.230.132.75:8000/api/scans/41/ | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")
  echo "Status: $STATUS"
  [ "$STATUS" = "completed" ] && break
  sleep 60
done

# 6. Get subdomains
curl -b /tmp/cookies.txt \
  http://173.230.132.75:8000/api/scans/41/subdomains/ | python3 -m json.tool

# 7. Get ports
curl -b /tmp/cookies.txt \
  http://173.230.132.75:8000/api/scans/41/ports/ | python3 -m json.tool

# 8. Run nuclei on a specific subdomain
curl -b /tmp/cookies.txt \
  -X POST http://173.230.132.75:8000/api/scans/41/nuclei-sub/1700/

# 9. Wait for nuclei results
while true; do
  curl -b /tmp/cookies.txt -s \
    http://173.230.132.75:8000/api/scans/41/nuclei-sub/1700/status/ | \
    python3 -c "import sys,json; d=json.load(sys.stdin); print(f'running={d[\"running\"]} findings={d[\"findings\"]}')"
  [ "$(curl -b /tmp/cookies.txt -s \
    http://173.230.132.75:8000/api/scans/41/nuclei-sub/1700/status/ | \
    python3 -c "import sys,json; print(json.load(sys.stdin)['running'])")" = "False" ] && break
  sleep 30
done

# 10. Get all findings
curl -b /tmp/cookies.txt \
  http://173.230.132.75:8000/api/scans/41/nuclei/ | python3 -m json.tool
```

### 15.2 Run ASN Discovery

```bash
# 1. Log in
curl -c /tmp/cookies.txt \
  -X POST http://173.230.132.75:8000/login/ \
  -d "username=killer_doddle&password=Cremated123@"

# 2. Start ASN scan
curl -b /tmp/cookies.txt \
  -X POST http://173.230.132.75:8000/api/organisations/10/asn_scan/

# 3. Poll until completed
while true; do
  curl -b /tmp/cookies.txt -s \
    http://173.230.132.75:8000/api/organisations/10/ | \
    python3 -c "
import sys,json
d = json.load(sys.stdin)
print(f'status={d[\"asn_status\"]} cidrs={d[\"asn_cidr_count\"]} ips={d[\"asn_ip_count\"]}')
if d['asn_status'] == 'completed': sys.exit(0)
"
  sleep 60
done
```

---

## 16. GitHub Workflow

The repository is `git@github.com:lordseidon/recon-vps.git`.

### 16.1 Push Code

```
cd /home/lordseidon/recon/recon_web
git add -A
git commit -m "Description of change"
git push origin master
```

### 16.2 Deploy to VPS

```
ssh root@173.230.132.75
cd /opt/recon_web
git pull
rm -rf scanner/__pycache__/
```

Django reloads automatically.  
Restart celery if you changed scanner/tasks.py:

```
pkill -f "celery.*worker"
cd /opt/recon_web
source .venv/bin/activate
export PYTHONPATH=/opt/recon_web
nohup .venv/bin/celery -A recon_web worker --loglevel=info --concurrency=2 > /tmp/celery.log 2>&1 &
```

---

## 17. Key Paths on the VPS

| Path | Purpose |
|------|---------|
| `/opt/recon_web/` | ReconVue Django project |
| `/opt/recon_web/scripts/` | Bash scripts (recon.sh, portscan.sh, nuclei.sh, asn_scan.sh) |
| `/opt/recon_web/scanner/` | Django app (models, views, tasks, templates) |
| `/opt/recon_web/outputs/` | Scan output files |
| `/opt/recon_web/outputs/<domain>/<date>/` | Per-scan output |
| `/opt/wordlists/subdomains.txt` | 114,000 DNS brute-force wordlist |
| `/opt/wordlists/altdns-words.txt` | 224 permutation wordlist |
| `/root/go/bin/` | Go tools directory |
| `/root/resolvers.txt` | DNS resolver (127.0.0.1) |
| `/tmp/celery.log` | Celery worker log |
