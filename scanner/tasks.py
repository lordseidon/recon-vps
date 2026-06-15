import os
import subprocess
from datetime import datetime
from celery import shared_task
from django.utils import timezone
from django.conf import settings
from pathlib import Path

from .models import Project, Scan, ScanLog, ScanProgress, Organisation, ASNCIDR, Subdomain, NucleiFinding
from .parsers import parse_http_info


def _emit_log(scan, category, message, data=None):
    ScanLog.objects.create(scan=scan, category=category, message=message, data=data or {})


def _update_progress(scan, **kwargs):
    prog, _ = ScanProgress.objects.get_or_create(scan=scan)
    for k, v in kwargs.items():
        setattr(prog, k, v)
    prog.save()


def _populate_counts_from_files(output_base):
    """Read counts from existing output files — called on resume."""
    result = {}
    try:
        sub_file = output_base / "all-subdomains.txt"
        if sub_file.exists():
            result["subs_found"] = max(0, sum(1 for _ in open(sub_file, errors="replace") if _.strip()))
        dns_file = output_base / "resolved-dns.txt"
        if dns_file.exists():
            result["subs_resolved"] = max(0, sum(1 for _ in open(dns_file, errors="replace") if _.strip()))
        live_file = output_base / "resolved_domain.txt"
        if live_file.exists():
            result["subs_live"] = max(0, sum(1 for _ in open(live_file, errors="replace") if _.strip()))
        ports_file = output_base / "ports" / "open-ports.json"
        if ports_file.exists():
            import json
            data = json.load(open(ports_file))
            result["ports_found"] = sum(len(e.get("ports", [])) for e in data)
    except Exception:
        pass
    return result


@shared_task(bind=True, time_limit=7200)
def run_scan_pipeline(self, scan_id):
    try:
        scan = Scan.objects.get(id=scan_id)
    except Scan.DoesNotExist:
        return {"error": "Scan not found"}

    scan.status = "running"
    scan.save(update_fields=["status", "task_id"])

    project = scan.project
    domain = project.domain
    date_str = scan.scan_date.strftime("%d-%m-%Y")

    output_base = settings.RECON_BASE_DIR / domain / date_str
    # Clean old output for fresh start
    import shutil
    if output_base.exists():
        shutil.rmtree(str(output_base))
    output_base.mkdir(parents=True, exist_ok=True)

    scan.output_dir = str(output_base)
    scan.save(update_fields=["output_dir"])

    scripts_dir = settings.RECON_SCRIPTS_DIR
    env = {}
    for k, v in os.environ.items():
        if not k.startswith(('GOPATH', 'GOROOT', 'GOMODCACHE', 'GOCACHE')):
            env[k] = v
    env["HOME"] = "/root"
    env["PATH"] = "/root/go/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:" + env.get("PATH", "")
    env["RECON_OUTPUT_DIR"] = str(output_base)
    env["RECON_SCRIPTS_DIR"] = str(scripts_dir)
    env["DOMAIN"] = domain

    steps = [
        ("recon", "recon.sh", "Subdomain Enumeration & DNS"),
        ("portscan", "portscan.sh", "Port Scanning"),
        ("probe", "probe.sh", "HTTP Probing"),
        ("dork", "dork.sh", "Google Dorks"),
        ("linkgather", "linkgatherer.sh", "Link Gathering & Secrets"),
        ("takeover", "takeover.sh", "Takeover Check"),
        ("s3", "s3_scanner.sh", "S3 Bucket Scan"),
        ("xss", "xss.sh", "XSS Scanning"),
    ]

    _update_progress(scan, step_index=0, step_total=len(steps), message="Starting pipeline...")

    STEP_OUTPUTS = {
        "recon": ["resolved-dns.txt", "resolved_domain.txt"],
        "portscan": ["ports/open-ports.json"],
        "probe": ["probe-output.json"],
        "dork": ["dorks.json"],
        "linkgather": ["linkgather/katana.json"],
        "takeover": ["takeover.json"],
        "s3": ["s3/s3-buckets.txt"],
        "xss": ["xss-findings.json"],
    }

    for idx, (step_key, script, label) in enumerate(steps):
        script_path = scripts_dir / script

        # Check if this step's output already exists — skip if done
        expected_files = STEP_OUTPUTS.get(step_key, [])
        skip_this = False
        if expected_files:
            skip_this = all(
                (output_base / f).exists() and (output_base / f).stat().st_size > 0
                for f in expected_files
            )
        if skip_this:
            _update_progress(
                scan, step=label, step_index=idx + 1, step_total=len(steps),
                message=f"Skipping {label} (already completed)"
            )
            _emit_log(scan, "step", f"[{idx+1}/{len(steps)}] Skipping {label} — output files exist")
            continue

        if not script_path.exists():
            _emit_log(scan, "warn", f"Script not found: {script}")
            continue

        _update_progress(
            scan, step=label, step_index=idx + 1, step_total=len(steps),
            message=f"Running {label}..."
        )
        _emit_log(scan, "step", f"[{idx+1}/{len(steps)}] {label}")

        self.update_state(state="RUNNING", meta={"step": label})

        try:
            proc = subprocess.Popen(
                ["bash", str(script_path), domain],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, cwd=str(output_base), env=env,
            )

            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue

                _emit_log(scan, "output", line)

                # Parse live data from output
                if step_key == "recon":
                    if ".mtn." in line or f".{domain}" in line or "subfinder" in line.lower() or "amass" in line.lower():
                        parts = line.split()
                        for word in parts:
                            if word.endswith(f".{domain}") and len(word) > len(domain) + 2:
                                _emit_log(scan, "subdomain", word, {"source": script})
                                p = ScanProgress.objects.get(scan=scan)
                                p.subs_found += 1
                                p.save(update_fields=["subs_found"])

                elif step_key == "portscan":
                    if "port" in line.lower() or "open" in line.lower():
                        try:
                            import json
                            obj = json.loads(line)
                            if "port" in obj:
                                p = ScanProgress.objects.get(scan=scan)
                                p.ports_found += 1
                                p.save(update_fields=["ports_found"])
                                _emit_log(scan, "port", f"{obj.get('host','')}:{obj['port']}", obj)
                        except Exception:
                            pass

                elif step_key == "nuclei":
                    try:
                        import json
                        obj = json.loads(line)
                        if "template-id" in obj:
                            p = ScanProgress.objects.get(scan=scan)
                            p.nuclei_found += 1
                            p.save(update_fields=["nuclei_found"])
                            sev = obj.get("info", {}).get("severity", "unknown")
                            _emit_log(scan, "finding", f"[{sev}] {obj.get('template-id','')}", obj)
                    except Exception:
                        pass

                elif step_key == "linkgather":
                    if "Secrets found" in line:
                        try:
                            n = int(line.split(":")[-1].strip())
                            p = ScanProgress.objects.get(scan=scan)
                            p.secrets_found = n
                            p.save(update_fields=["secrets_found"])
                        except:
                            pass

            proc.wait(timeout=1800)

            if proc.returncode == 0:
                _emit_log(scan, "success", f"Completed: {label}")
            else:
                _emit_log(scan, "error", f"Failed: {label} (exit {proc.returncode})")

        except subprocess.TimeoutExpired:
            proc.kill()
            _emit_log(scan, "error", f"Timeout: {label}")
        except Exception as e:
            _emit_log(scan, "error", f"Error in {label}: {str(e)}")

        # Live parse HTTP info after recon & probe
        if step_key in ("recon", "probe"):
            try:
                http_info = parse_http_info(output_base)
                subs_resolved = 0
                subs_live = 0
                dns_file = output_base / "resolved-dns.txt"
                if dns_file.exists():
                    subs_resolved = sum(1 for _ in open(dns_file))
                subs_live = len(http_info)
                _update_progress(scan, subs_resolved=subs_resolved, subs_live=subs_live)
            except Exception:
                pass

    # Launch nuclei in background (doesn't block pipeline)
    nuclei_script = scripts_dir / "nuclei.sh"
    ports_file = output_base / "ports" / "open-ports.json"
    if nuclei_script.exists() and ports_file.exists() and ports_file.stat().st_size > 0:
        _emit_log(scan, "step", "Nuclei scanning started in background — findings will appear when ready")
        subprocess.Popen(
            ["bash", str(nuclei_script), domain],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            cwd=str(output_base), env=env,
        )

    _update_progress(scan, step="Importing data...", message="Importing scan results into database")
    _emit_log(scan, "step", "Importing all results into database...")

    try:
        from .tasks_import import _import_scan_data
        _import_scan_data(scan, output_base)
    except Exception as e:
        scan.error_message = f"Import error: {str(e)}"
        scan.status = "failed"
        scan.save()
        _emit_log(scan, "error", f"Import failed: {str(e)}")
        return {"error": str(e)}

    scan.status = "completed"
    scan.completed_at = timezone.now()
    scan.save()
    _update_progress(scan, step="Complete", message="Scan finished successfully")
    _emit_log(scan, "success", f"Scan complete — {scan.subdomain_count} subs, {scan.live_count} live")

    return {"status": "completed", "summary": {
        "subdomains": scan.subdomain_count,
        "live": scan.live_count,
        "ports": scan.port_count,
        "nuclei": scan.nuclei_finding_count,
        "secrets": scan.secret_count,
        "api_endpoints": scan.api_endpoint_count,
    }}



# ── Organisation-Level ASN Discovery ──

@shared_task(bind=True, time_limit=10800)
def run_org_asn_discovery(self, org_id):
    try:
        org = Organisation.objects.get(id=org_id)
    except Organisation.DoesNotExist:
        return {"error": "Organisation not found"}

    org.asn_status = "running"
    org.save(update_fields=["asn_status"])

    scripts_dir = settings.RECON_SCRIPTS_DIR
    output_base = settings.RECON_BASE_DIR / "organisations" / org.slug
    output_base.mkdir(parents=True, exist_ok=True)

    env = {}
    for k, v in os.environ.items():
        if not k.startswith(('GOPATH', 'GOROOT', 'GOMODCACHE', 'GOCACHE')):
            env[k] = v
    env["HOME"] = "/root"
    env["RECON_OUTPUT_DIR"] = str(output_base)
    env["DOMAIN"] = org.name
    env["PATH"] = "/root/go/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:" + env.get("PATH", "")

    _emit_org_log(org, "step", f"Starting ASN discovery for {org.name}")

    # Run asn_scan.sh
    script_path = scripts_dir / "asn_scan.sh"
    if not script_path.exists():
        org.asn_status = "failed"
        org.save()
        return {"error": "asn_scan.sh not found"}

    # Get the first linked domain as filter for whois/amass
    filter_domain = ""
    first_project = org.projects.first()
    if first_project:
        filter_domain = first_project.domain

    try:
        proc = subprocess.Popen(
            ["bash", str(script_path), org.name, filter_domain],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, cwd=str(output_base), env=env,
        )
        for line in proc.stdout:
            line = line.strip()
            if line:
                _emit_org_log(org, "output", line)
                # Live counter updates from output
                if "CIDRs:" in line:
                    try:
                        count = int(line.split(":")[-1].strip())
                        org.asn_cidr_count = count
                        org.save(update_fields=["asn_cidr_count"])
                    except ValueError:
                        pass
                elif '"port":' in line and '"ip":' in line:
                    org.asn_ip_count += 1
                    if org.asn_ip_count % 10 == 0:
                        org.save(update_fields=["asn_ip_count"])
                elif "Reverse DNS" in line or "TLS domains" in line:
                    try:
                        count = int(line.split(":")[-1].strip())
                        org.asn_domain_count += count
                        org.save(update_fields=["asn_domain_count"])
                    except ValueError:
                        pass
        proc.wait(timeout=3600)
    except subprocess.TimeoutExpired:
        proc.kill()
        _emit_org_log(org, "error", "ASN scan timed out (1h)")
    except Exception as e:
        _emit_org_log(org, "error", str(e))

        # Import discovered data
    asn_dir = output_base / "asn"
    try:
        import ipaddress

        # CIDRs
        cidr_file = asn_dir / "cidrs.txt"
        all_cidrs = []
        if cidr_file.exists():
            all_cidrs = [l.strip() for l in open(cidr_file) if l.strip() and "/" in l]

        # Open IPs - group by CIDR
        ips_file = asn_dir / "ips-open.txt"
        cidr_ips = {}
        if ips_file.exists():
            for line in open(ips_file):
                ip_str = line.strip()
                if not ip_str:
                    continue
                try:
                    ip_obj = ipaddress.ip_address(ip_str)
                    for cidr_str in all_cidrs:
                        net = ipaddress.ip_network(cidr_str, strict=False)
                        if ip_obj in net:
                            cidr_ips.setdefault(cidr_str, []).append(ip_str)
                            break
                    else:
                        cidr_ips.setdefault("unknown", []).append(ip_str)
                except ValueError:
                    cidr_ips.setdefault("unknown", []).append(ip_str)

        # Upsert CIDRs instead of delete+create
        for cidr_str in all_cidrs:
            obj, _ = ASNCIDR.objects.update_or_create(
                organisation=org, cidr=cidr_str,
                defaults={"open_ips": sorted(cidr_ips.get(cidr_str, []))}
            )
        # Remove CIDRs no longer present
        ASNCIDR.objects.filter(organisation=org).exclude(cidr__in=all_cidrs).delete()
        org.asn_cidr_count = len(all_cidrs)
        org.asn_ip_count = sum(len(v) for v in cidr_ips.values())

        # Domains from TLS certs
        tls_file = asn_dir / "tls-domains.txt"
        discovered = set()
        if tls_file.exists():
            discovered.update(l.strip() for l in open(tls_file) if l.strip() and "." in l)

        # Domains from reverse DNS (cidr-subs.txt)
        rev_file = asn_dir / "cidr-subs.txt"
        if rev_file.exists():
            for line in open(rev_file):
                line = line.strip()
                if line and "." in line:
                    discovered.add(line)
        org.asn_domain_count = len(discovered)

        _emit_org_log(org, "success",
            f"ASN complete: {org.asn_cidr_count} CIDRs, {org.asn_ip_count} IPs, {org.asn_domain_count} domains")

    except Exception as e:
        _emit_org_log(org, "error", f"Import error: {str(e)}")

    org.asn_status = "completed"
    org.save()


@shared_task(bind=True, time_limit=600)
def run_single_nuclei(self, scan_id, subdomain_id, ports):
    """Run nuclei on a single subdomain with its open ports."""
    import tempfile, json
    from pathlib import Path
    from django.conf import settings

    try:
        scan = Scan.objects.get(id=scan_id)
        subdomain = Subdomain.objects.get(id=subdomain_id, scan=scan)
    except (Scan.DoesNotExist, Subdomain.DoesNotExist):
        return {"error": "Scan or subdomain not found"}

    nuclei_bin = Path("/root/go/bin/nuclei")
    if not nuclei_bin.exists():
        return {"error": "nuclei not installed"}

    targets = [f"{subdomain.name}:{p}" for p in ports]
    outdir = settings.RECON_BASE_DIR / scan.project.domain / scan.scan_date.strftime("%d-%m-%Y")
    outfile = outdir / f"nuclei-sub-{subdomain_id}.json"
    outdir.mkdir(parents=True, exist_ok=True)

    _emit_log(scan, "nuclei_start", f"Nuclei started for {subdomain.name} ({len(targets)} targets)", {
        "subdomain_id": subdomain_id, "subdomain": subdomain.name, "targets": len(targets)
    })

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        tf.write("\n".join(targets))
        targets_file = tf.name

    finding_output = []  # collect stdout lines

    try:
        import subprocess
        env = {}
        for k, v in os.environ.items():
            if not k.startswith(("GOPATH", "GOROOT", "GOMODCACHE", "GOCACHE")):
                env[k] = v
        env["HOME"] = "/root"
        env["PATH"] = "/root/go/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:" + env.get("PATH", "")

        proc = subprocess.Popen(
            [str(nuclei_bin), "-l", targets_file, "-as", "-nh", "-rl", "30", "-timeout", "10",
             "-o", str(outfile)],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, env=env,
        )
        for line in proc.stdout:
            line = line.strip()
            if line:
                finding_output.append(line)
                _emit_log(scan, "nuclei_output", line, {
                    "subdomain_id": subdomain_id, "subdomain": subdomain.name,
                })
        proc.wait(timeout=300)
    except subprocess.TimeoutExpired:
        proc.kill()
        _emit_log(scan, "nuclei_done", f"Nuclei on {subdomain.name} timed out", {
            "subdomain_id": subdomain_id, "subdomain": subdomain.name, "findings": 0
        })
        return {"status": "timeout", "findings": 0, "subdomain": subdomain.name}
    finally:
        Path(targets_file).unlink(missing_ok=True)

    if not outfile.exists() or outfile.stat().st_size == 0:
        _emit_log(scan, "nuclei_done", f"Nuclei on {subdomain.name} done: 0 findings", {
            "subdomain_id": subdomain_id, "subdomain": subdomain.name, "findings": 0
        })
        return {"status": "done", "findings": 0, "subdomain": subdomain.name}

    from .parsers import parse_nuclei
    raw = parse_nuclei(str(outfile))
    if raw:
        NucleiFinding.objects.bulk_create(
            [NucleiFinding(scan=scan, **entry) for entry in raw], batch_size=500)
    finding_count = len(raw)

    _emit_log(scan, "nuclei_done", f"Nuclei on {subdomain.name} done: {finding_count} findings", {
        "subdomain_id": subdomain_id, "subdomain": subdomain.name, "findings": finding_count
    })
    scan.nuclei_finding_count = NucleiFinding.objects.filter(scan=scan).count()
    scan.save(update_fields=["nuclei_finding_count"])

    return {"status": "done", "findings": finding_count, "subdomain": subdomain.name}


def _emit_org_log(org, category, message, data=None):
    from .models import ScanLog
    ScanLog.objects.create(scan=None, category=category, message=f"[{org.name}] {message}", data=data or {})

