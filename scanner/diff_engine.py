from deepdiff import DeepDiff


def run_diff(scan_a, scan_b):
    a_subs = list(
        scan_a.subdomains.values("name", "ip", "http_status", "http_title", "technologies")
    )
    b_subs = list(
        scan_b.subdomains.values("name", "ip", "http_status", "http_title", "technologies")
    )

    a_names = {s["name"] for s in a_subs}
    b_names = {s["name"] for s in b_subs}

    subdomain_diff = {
        "added": sorted(b_names - a_names),
        "removed": sorted(a_names - b_names),
        "changed": [],
    }

    a_map = {s["name"]: s for s in a_subs}
    b_map = {s["name"]: s for s in b_subs}
    for name in a_names & b_names:
        a_s = a_map[name]
        b_s = b_map[name]
        changes = {}
        for key in ["ip", "http_status", "http_title"]:
            if str(a_s.get(key, "")) != str(b_s.get(key, "")):
                changes[key] = {"old": a_s.get(key), "new": b_s.get(key)}
        a_tech = set(a_s.get("technologies", []) or [])
        b_tech = set(b_s.get("technologies", []) or [])
        tech_added = b_tech - a_tech
        tech_removed = a_tech - b_tech
        if tech_added or tech_removed:
            changes["technologies"] = {"added": list(tech_added), "removed": list(tech_removed)}
        if changes:
            subdomain_diff["changed"].append({"name": name, "changes": changes})

    a_port_map = {}
    from .models import Port
    for p in Port.objects.filter(subdomain__scan=scan_a).select_related("subdomain"):
        a_port_map.setdefault(p.subdomain.name, set()).add(p.port_number)
    b_port_map = {}
    for p in Port.objects.filter(subdomain__scan=scan_b).select_related("subdomain"):
        b_port_map.setdefault(p.subdomain.name, set()).add(p.port_number)

    port_diff = {"added": [], "removed": [], "changed": []}
    for name in set(a_port_map.keys()) | set(b_port_map.keys()):
        a_ports = a_port_map.get(name, set())
        b_ports = b_port_map.get(name, set())
        added = b_ports - a_ports
        removed = a_ports - b_ports
        if added or removed:
            port_diff["changed"].append({
                "subdomain": name,
                "ports_added": sorted(added),
                "ports_removed": sorted(removed),
            })

    a_nuclei_templates = set(
        scan_a.nuclei_findings.values_list("template_id", flat=True)
    )
    b_nuclei_templates = set(
        scan_b.nuclei_findings.values_list("template_id", flat=True)
    )
    nuclei_diff = {
        "added": sorted(b_nuclei_templates - a_nuclei_templates),
        "removed": sorted(a_nuclei_templates - b_nuclei_templates),
        "added_detailed": sorted(
            scan_b.nuclei_findings.exclude(template_id__in=a_nuclei_templates)
            .values("template_id", "severity", "matched_at"),
            key=lambda x: x["template_id"],
        ),
        "removed_detailed": sorted(
            scan_a.nuclei_findings.exclude(template_id__in=b_nuclei_templates)
            .values("template_id", "severity", "matched_at"),
            key=lambda x: x["template_id"],
        ),
    }

    from .models import APIEndpoint, Secret
    a_endpoints = set(scan_a.api_endpoints.values_list("url", flat=True))
    b_endpoints = set(scan_b.api_endpoints.values_list("url", flat=True))
    endpoint_diff = {
        "added": sorted(b_endpoints - a_endpoints),
        "removed": sorted(a_endpoints - b_endpoints),
    }

    a_secrets = set(scan_a.secrets.values_list("detector_name", flat=True))
    b_secrets = set(scan_b.secrets.values_list("detector_name", flat=True))
    secret_diff = {
        "added": sorted(b_secrets - a_secrets),
        "removed": sorted(a_secrets - b_secrets),
    }

    a_takeovers = set(
        scan_a.takeovers.filter(vulnerable=True).values_list("subdomain_name", flat=True)
    )
    b_takeovers = set(
        scan_b.takeovers.filter(vulnerable=True).values_list("subdomain_name", flat=True)
    )
    takeover_diff = {
        "added": sorted(b_takeovers - a_takeovers),
        "removed": sorted(a_takeovers - b_takeovers),
    }

    a_s3 = set(scan_a.s3_buckets.values_list("bucket_name", flat=True))
    b_s3 = set(scan_b.s3_buckets.values_list("bucket_name", flat=True))
    s3_diff = {
        "added": sorted(b_s3 - a_s3),
        "removed": sorted(a_s3 - b_s3),
    }

    a_xss = set(scan_a.xss_findings.values_list("url", flat=True))
    b_xss = set(scan_b.xss_findings.values_list("url", flat=True))
    xss_diff = {
        "added": sorted(b_xss - a_xss),
        "removed": sorted(a_xss - b_xss),
    }

    return {
        "scan_a": {"id": scan_a.id, "date": scan_a.scan_date.isoformat()},
        "scan_b": {"id": scan_b.id, "date": scan_b.scan_date.isoformat()},
        "summary": {
            "subdomains": {
                "a": len(a_subs), "b": len(b_subs),
                "added": len(subdomain_diff["added"]),
                "removed": len(subdomain_diff["removed"]),
                "changed": len(subdomain_diff["changed"]),
            },
            "nuclei": {
                "a": len(a_nuclei_templates), "b": len(b_nuclei_templates),
                "added": len(nuclei_diff["added"]),
                "removed": len(nuclei_diff["removed"]),
            },
            "endpoints": {
                "a": len(a_endpoints), "b": len(b_endpoints),
                "added": len(endpoint_diff["added"]),
                "removed": len(endpoint_diff["removed"]),
            },
            "secrets": {
                "a": len(a_secrets), "b": len(b_secrets),
                "added": len(secret_diff["added"]),
                "removed": len(secret_diff["removed"]),
            },
            "takeover": {
                "a": len(a_takeovers), "b": len(b_takeovers),
                "added": len(takeover_diff["added"]),
                "removed": len(takeover_diff["removed"]),
            },
            "s3": {
                "a": len(a_s3), "b": len(b_s3),
                "added": len(s3_diff["added"]),
                "removed": len(s3_diff["removed"]),
            },
            "xss": {
                "a": len(a_xss), "b": len(b_xss),
                "added": len(xss_diff["added"]),
                "removed": len(xss_diff["removed"]),
            },
        },
        "subdomains": subdomain_diff,
        "ports": port_diff,
        "nuclei": nuclei_diff,
        "endpoints": endpoint_diff,
        "secrets": secret_diff,
        "takeover": takeover_diff,
        "s3": s3_diff,
        "xss": xss_diff,
    }
