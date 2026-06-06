import json
import re
import os
from pathlib import Path


def parse_all_sources(output_dir):
    """Parse ALL subdomain sources and return a dict {name: {sources:[], resolved:bool, ip:'', record_type:''}}"""
    results = {}

    def add_sub(name, source, ip="", record_type=""):
        if not name or "." not in name:
            return
        name = name.strip()
        if name not in results:
            results[name] = {"sources": [], "resolved": False, "ip": "", "record_type": ""}
        if source not in results[name]["sources"]:
            results[name]["sources"].append(source)
        if ip:
            results[name]["ip"] = ip
        if record_type:
            results[name]["record_type"] = record_type

    # subfinder
    f = output_dir / "subfinder.txt"
    if f.exists():
        with open(f) as fh:
            for line in fh:
                line = line.strip()
                if line and "." in line and not line.startswith("#"):
                    add_sub(line, "subfinder")

    # amass
    f = output_dir / "amass.txt"
    if f.exists():
        with open(f) as fh:
            for line in fh:
                line = line.strip()
                if " --> " in line:
                    parts = line.split(" --> ")
                    if parts:
                        name = parts[0].replace(" (FQDN)", "").strip()
                        if name and "." in name:
                            add_sub(name, "amass")

    # shuffledns
    f = output_dir / "shuffledns.txt"
    if f.exists():
        with open(f) as fh:
            for line in fh:
                line = line.strip()
                if line and "." in line:
                    add_sub(line, "shuffledns")

    # all-subdomains (merged)
    f = output_dir / "all-subdomains.txt"
    if f.exists():
        with open(f) as fh:
            for line in fh:
                line = line.strip()
                if line and "." in line and not line.startswith("#"):
                    add_sub(line, "merged")

    # altdns resolved
    f = output_dir / "altdns-resolved.txt"
    if f.exists():
        with open(f) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                match = re.match(r"^(\S+)", line)
                if match:
                    add_sub(match.group(1), "altdns")

    # altdns valid
    for alt_f in ["altdns-valid.txt", "altdns-new.txt"]:
        f = output_dir / alt_f
        if f.exists():
            with open(f) as fh:
                for line in fh:
                    line = line.strip()
                    if line and "." in line:
                        add_sub(line, "altdns")

    # DNS resolution marks subs as resolved
    f = output_dir / "resolved-dns.txt"
    if f.exists():
        with open(f) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                match = re.match(r"^(\S+)\s+\[(\w+)\]\s+\[([^\]]+)\]", line)
                if match:
                    name = match.group(1)
                    add_sub(name, "dns_resolved", ip=match.group(3), record_type=match.group(2))

    # Mark all with IP as resolved
    for name, data in results.items():
        if data["ip"]:
            data["resolved"] = True
        if "dns_resolved" in data["sources"]:
            data["resolved"] = True

    return results


def parse_http_info(output_dir):
    """Parse resolved.txt or probe-output.json for HTTP info. Returns {name: {http_url, http_status, http_title, technologies}}"""
    http_map = {}

    # Try probe-output.json first (httpx JSON output)
    f = output_dir / "probe-output.json"
    if f.exists():
        with open(f) as fh:
            try:
                data = json.load(fh)
            except json.JSONDecodeError:
                data = []
            if isinstance(data, dict):
                data = [data]
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                url = entry.get("url", "")
                if not url:
                    continue
                name = url.replace("https://", "").replace("http://", "").split(":")[0].rstrip("/")
                http_map[name] = {
                    "http_url": url,
                    "http_status": entry.get("status_code"),
                    "http_title": entry.get("title", ""),
                    "technologies": entry.get("technologies", []) or [],
                }

    # Also try resolved.txt
    f = output_dir / "resolved.txt"
    if f.exists():
        with open(f) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                match = re.match(r"^(\S+)\s+\[(\d+)\]\s+\[(.*?)\]\s+\[(.*?)\]$", line)
                if match:
                    name = match.group(1).replace("https://", "").replace("http://", "").split(":")[0].rstrip("/")
                    if name not in http_map:
                        http_map[name] = {
                            "http_url": match.group(1),
                            "http_status": int(match.group(2)),
                            "http_title": match.group(3),
                            "technologies": [t.strip() for t in match.group(4).split(",") if t.strip()],
                        }

    return http_map


def parse_open_ports(filepath):
    if not os.path.isfile(filepath):
        return []
    with open(filepath) as f:
        return json.load(f)


def parse_nuclei(filepath):
    findings = []
    if not os.path.isfile(filepath):
        return findings
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                info = obj.get("info", {})
                findings.append({
                    "template_id": obj.get("template-id", obj.get("templateID", "")),
                    "name": info.get("name", ""),
                    "severity": info.get("severity", obj.get("severity", "unknown")),
                    "matched_at": obj.get("matched-at", obj.get("matched", "")),
                    "extracted_results": "\n".join(obj.get("extracted-results", []))
                    if isinstance(obj.get("extracted-results"), list)
                    else str(obj.get("extracted-results", "")),
                    "curl_command": obj.get("curl-command", obj.get("curl_command", "")),
                    "host": obj.get("host", ""),
                    "ip": obj.get("ip", ""),
                    "raw_data": obj,
                })
            except json.JSONDecodeError:
                pass
    return findings


def parse_katana(filepath, output_base=None):
    """Parse katana.json into CrawledURL entries and API endpoints. Returns (crawled[], api_endpoints[])."""
    crawled = []
    api_endpoints = []
    if not os.path.isfile(filepath):
        return crawled, api_endpoints

    if output_base is None:
        output_base = Path(filepath).parent.parent  # linkgather -> scan dir

    with open(filepath) as f:
        try:
            entries = json.load(f)
        except json.JSONDecodeError:
            return crawled, api_endpoints

    for entry in entries:
        base = entry.get("base_url", "")
        for url in entry.get("extracted_urls", []):
            if not url:
                continue
            is_js = url.lower().endswith(".js")
            is_api = bool(re.search(
                r"/api/|/graphql|/v[0-9]+/|swagger|openapi|/auth|/oauth|/rest/|"
                r"/token|/login|/signin|/signup|\.json($|\?)|\.php\?|/wp-json|/wp-admin|"
                r"/admin/|/dashboard/|\.do\?|/ajax/|/xmlrpc|/soap",
                url, re.I,
            ))

            local_path = ""
            if is_js and output_base:
                js_name = os.path.basename(url.split("?")[0])
                local_path = str(output_base / "linkgather" / "js" / f"{base}__{js_name}")

            crawled.append({
                "subdomain": base,
                "url": url,
                "is_js": is_js,
                "is_api": is_api,
                "local_path": local_path,
            })
            if is_api:
                api_endpoints.append({
                    "subdomain": base,
                    "url": url,
                    "source": "katana",
                })

    return crawled, api_endpoints


def parse_api_endpoints_file(filepath):
    """Parse api-endpoints.txt for regex-extracted endpoints."""
    endpoints = []
    if not os.path.isfile(filepath):
        return endpoints
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line:
                endpoints.append({
                    "subdomain": "",
                    "url": line,
                    "source": "regex",
                })
    return endpoints


def parse_trufflehog(filepath):
    secrets = []
    if not os.path.isfile(filepath):
        return secrets
    with open(filepath) as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return secrets

    if isinstance(data, list):
        for obj in data:
            meta = obj.get("SourceMetadata", {})
            file_path = ""
            if "Data" in meta and isinstance(meta["Data"], dict):
                fs = meta["Data"].get("Filesystem", {})
                if isinstance(fs, dict):
                    file_path = fs.get("file", "")
            secrets.append({
                "detector_name": obj.get("DetectorName", obj.get("detector_name", "")),
                "verified": obj.get("Verified", False),
                "raw": obj.get("Raw", ""),
                "raw_v2": obj.get("RawV2", ""),
                "file_path": file_path,
                "source_metadata": meta,
            })
    return secrets


def parse_takeover(filepath):
    if not os.path.isfile(filepath):
        return []
    with open(filepath) as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return []

    results = []
    for obj in data:
        results.append({
            "subdomain_name": obj.get("subdomain", ""),
            "vulnerable": obj.get("vulnerable", False),
            "service": obj.get("service", ""),
        })
    return results


def parse_s3(filepath):
    if not os.path.isfile(filepath):
        return []
    with open(filepath) as f:
        return [{"bucket_name": line.strip(), "is_open": True} for line in f if line.strip()]


def parse_xss(filepath):
    if not os.path.isfile(filepath):
        return []
    with open(filepath) as f:
        try:
            data = json.load(f)
            if isinstance(data, dict):
                data = [data]
        except json.JSONDecodeError:
            return []
    if not isinstance(data, list):
        return []
    return [{"url": obj.get("url", ""), "poc": obj.get("poc", "")} for obj in data if isinstance(obj, dict)]


def parse_dorks(filepath):
    entries = []
    if not os.path.isfile(filepath):
        return entries
    with open(filepath) as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            return entries
    if isinstance(data, dict):
        for sub, dorks in data.items():
            for dork_str in dorks:
                entries.append({
                    "subdomain_name": sub,
                    "dork_type": "google",
                    "query": dork_str,
                })
    return entries


def parse_all_subdomains_txt(filepath):
    if not os.path.isfile(filepath):
        return []
    with open(filepath) as f:
        return sorted(set(l.strip() for l in f if l.strip() and "." in l and not l.startswith("#")))
