from .models import (
    Subdomain, Port, NucleiFinding, Dork, CrawledURL, APIEndpoint,
    Secret, S3Bucket, Takeover, XSSFinding,
)
from .parsers import (
    parse_all_sources, parse_http_info, parse_open_ports,
    parse_nuclei, parse_katana, parse_api_endpoints_file,
    parse_trufflehog, parse_takeover, parse_s3, parse_xss, parse_dorks,
)


def _import_scan_data(scan, output_base):
    base = output_base
    all_subs = parse_all_sources(base)
    http_map = parse_http_info(base)

    sub_objects = []
    for name, data in all_subs.items():
        http_info = http_map.get(name, {})
        sub_objects.append(Subdomain(
            scan=scan, name=name, ip=data.get("ip", ""),
            record_type=data.get("record_type", "A"),
            resolved=data.get("resolved", False),
            http_url=http_info.get("http_url", ""),
            http_status=http_info.get("http_status"),
            http_title=http_info.get("http_title", ""),
            technologies=http_info.get("technologies", []),
            sources=data.get("sources", []),
        ))

    existing_names = {s.name for s in sub_objects}
    for name, http_info in http_map.items():
        if name not in existing_names:
            sub_objects.append(Subdomain(
                scan=scan, name=name, resolved=True,
                http_url=http_info.get("http_url", ""),
                http_status=http_info.get("http_status"),
                http_title=http_info.get("http_title", ""),
                technologies=http_info.get("technologies", []),
                sources=["httpx"],
            ))

    Subdomain.objects.bulk_create(sub_objects, batch_size=500)

    ports_file = base / "ports" / "open-ports.json"
    ports_data = parse_open_ports(str(ports_file))
    subdomain_map = {s.name: s for s in Subdomain.objects.filter(scan=scan)}
    ports_to_create = []
    for entry in ports_data:
        sub = subdomain_map.get(entry.get("subdomain", ""))
        if sub:
            for p in entry.get("ports", []):
                ports_to_create.append(Port(subdomain=sub, port_number=int(p)))
    if ports_to_create:
        Port.objects.bulk_create(ports_to_create, batch_size=500, ignore_conflicts=True)

    nuclei_file = base / "nuclei" / "findings.txt"
    nuclei_entries = parse_nuclei(str(nuclei_file))
    if nuclei_entries:
        NucleiFinding.objects.bulk_create(
            [NucleiFinding(scan=scan, **e) for e in nuclei_entries], batch_size=500)

    katana_file = base / "linkgather" / "katana.json"
    crawled_entries, katana_apis = parse_katana(str(katana_file), output_base=base)
    if crawled_entries:
        CrawledURL.objects.bulk_create(
            [CrawledURL(scan=scan, **e) for e in crawled_entries], batch_size=500)

    api_entries = list(katana_apis)
    api_file = base / "linkgather" / "api-endpoints.txt"
    api_entries.extend(parse_api_endpoints_file(str(api_file)))
    if api_entries:
        APIEndpoint.objects.bulk_create(
            [APIEndpoint(scan=scan, **e) for e in api_entries], batch_size=500)

    truffle_file = base / "linkgather" / "trufflehog.json"
    secrets = parse_trufflehog(str(truffle_file))
    if secrets:
        Secret.objects.bulk_create(
            [Secret(scan=scan, **e) for e in secrets], batch_size=500)

    takeover_file = base / "takeover.json"
    takeovers = parse_takeover(str(takeover_file))
    if takeovers:
        Takeover.objects.bulk_create(
            [Takeover(scan=scan, **e) for e in takeovers], batch_size=500)

    s3_file = base / "s3" / "s3-buckets.txt"
    s3_entries = parse_s3(str(s3_file))
    if s3_entries:
        S3Bucket.objects.bulk_create(
            [S3Bucket(scan=scan, **e) for e in s3_entries], batch_size=500)

    xss_file = base / "xss-findings.json"
    xss_entries = parse_xss(str(xss_file))
    if xss_entries:
        XSSFinding.objects.bulk_create(
            [XSSFinding(scan=scan, **e) for e in xss_entries], batch_size=500)

    dorks_file = base / "dorks.json"
    dork_entries = parse_dorks(str(dorks_file))
    if dork_entries:
        Dork.objects.bulk_create(
            [Dork(scan=scan, **e) for e in dork_entries], batch_size=500)

    scan.subdomain_count = Subdomain.objects.filter(scan=scan).count()
    scan.resolved_count = Subdomain.objects.filter(scan=scan, resolved=True).count()
    scan.live_count = Subdomain.objects.filter(scan=scan, http_status__isnull=False).count()
    scan.port_count = Port.objects.filter(subdomain__scan=scan).count()
    scan.nuclei_finding_count = NucleiFinding.objects.filter(scan=scan).count()
    scan.secret_count = Secret.objects.filter(scan=scan).count()
    scan.api_endpoint_count = APIEndpoint.objects.filter(scan=scan).count()
    scan.takeover_count = Takeover.objects.filter(scan=scan, vulnerable=True).count()
    scan.s3_bucket_count = S3Bucket.objects.filter(scan=scan).count()
    scan.xss_finding_count = XSSFinding.objects.filter(scan=scan).count()
    scan.save()
