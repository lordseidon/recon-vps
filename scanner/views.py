import json
import os
from django.shortcuts import render, redirect, get_object_or_404
from django.http import JsonResponse, HttpResponse
from django.contrib import messages
from django.utils import timezone
from django.db import models
from django.db.models import Count, Q
from django.views.decorators.http import require_POST
from rest_framework import viewsets, status
from rest_framework.decorators import action, api_view
from rest_framework.response import Response

from .models import (
    Project, Scan, Subdomain, Port, NucleiFinding,
    Dork, CrawledURL, APIEndpoint, Secret, S3Bucket,
    Takeover, XSSFinding, DiffResult, Keyword, ScanLog,
    Organisation, ASNCIDR,
)
from .serializers import (
    ProjectSerializer, ScanSerializer, SubdomainSerializer,
    SubdomainListSerializer, PortSerializer, NucleiFindingSerializer,
    DorkSerializer, APIEndpointSerializer, CrawledURLSerializer,
    SecretSerializer, S3BucketSerializer, TakeoverSerializer,
    XSSFindingSerializer, DiffResultSerializer, KeywordSerializer,
    OrganisationSerializer,
)
from .tasks import run_scan_pipeline, run_org_asn_discovery
from .diff_engine import run_diff


# ── Template Views ──


def dashboard(request):
    projects = Project.objects.annotate(
        scan_count=Count("scans")
    ).order_by("-created_at")
    return render(request, "scanner/dashboard.html", {"projects": projects})

projects_list = dashboard  # alias


def project_detail(request, project_id):
    project = get_object_or_404(Project, id=project_id)
    scans = project.scans.order_by("-created_at")
    return render(
        request,
        "scanner/project_detail.html",
        {"project": project, "scans": scans},
    )


@require_POST
def test_dns(request, project_id):
    project = get_object_or_404(Project, id=project_id)
    import subprocess, tempfile, os
    gobin = os.path.expanduser("~/go/bin")
    
    # Create small test wordlist
    test_words = ["www","mail","ftp","admin","api","dev","staging","portal","webmail","cpanel",
                  "blog","shop","cdn","remote","vpn","app","secure","auth","db","ns1","ns2",
                  "test","demo","login","support","help","status","monitor","dashboard","docs",
                  "mobile","m","beta","old","new","prod","uat","qa","sandbox","backup",
                  "cloud","host","server","web","site","intranet","internal","external",
                  "partner","customers","client","media","static","assets","files","download",
                  "upload","images","img","video","data","storage","cdn1","cdn2","edge",
                  "cache","proxy","gateway","api1","api2","rest","graphql","ws","soap",
                  "smtp","pop3","imap","ldap","sso","saml","oauth","openid","kerberos",
                  "mysql","oracle","redis","mongo","elastic","kibana","grafana","prometheus",
                  "jenkins","gitlab","bitbucket","jira","confluence","slack","teams"]
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        for w in test_words:
            f.write(f"{w}.{project.domain}\n")
        wordlist_path = f.name
    
    try:
        result = subprocess.run(
            [f"{gobin}/shuffledns", "-d", project.domain, "-w", wordlist_path,
             "-r", "/opt/wordlists/resolvers.txt",
             "-mode", "bruteforce", "-silent"],
            capture_output=True, text=True, timeout=30,
            env={**os.environ, "PATH": f"{gobin}:/usr/local/bin:{os.environ.get('PATH','')}"}
        )
        found = [l.strip() for l in result.stdout.splitlines() if l.strip() and not l.startswith('[')]
        return JsonResponse({
            "success": result.returncode == 0,
            "exit_code": result.returncode,
            "found": len(found),
            "subdomains": found[:20],
            "stderr": result.stderr[-500:] if result.stderr else "",
        })
    except subprocess.TimeoutExpired:
        return JsonResponse({"success": False, "error": "Timeout (30s) — DNS may be blocked"})
    except FileNotFoundError:
        return JsonResponse({"success": False, "error": "shuffledns or massdns not found in PATH"})
    finally:
        os.unlink(wordlist_path)


@require_POST
def delete_project(request, project_id):
    project = get_object_or_404(Project, id=project_id)
    # Kill any running scan processes
    import subprocess
    for scan in project.scans.filter(status="running"):
        if scan.task_id:
            subprocess.run(["pkill", "-f", f"recon.sh.*{project.domain}"], check=False)
            subprocess.run(["pkill", "-f", f"nuclei.*{project.domain}"], check=False)
            from celery import current_app
            current_app.control.revoke(scan.task_id, terminate=True)
        scan.delete()
    org_id = project.organisation.id if project.organisation else None
    project.delete()
    messages.success(request, f"Deleted project and all its scans")
    if org_id:
        return redirect("org_detail", org_id=org_id)
    return redirect("projects_list")


@require_POST
def start_scan(request, project_id):
    project = get_object_or_404(Project, id=project_id)
    today = timezone.now().date()

    existing = Scan.objects.filter(project=project, scan_date=today).first()
    if existing:
        messages.warning(request, f"Scan for today ({today}) already exists.")
        return redirect("project_detail", project_id=project.id)

    scan = Scan.objects.create(project=project, scan_date=today, status="pending")
    task = run_scan_pipeline.delay(scan.id)
    scan.task_id = task.id
    scan.save(update_fields=["task_id"])

    messages.success(request, f"Scan started for {project.domain} on {today}")
    return redirect("live_scan", scan_id=scan.id)


def scan_detail(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    project = scan.project
    context = {
        "project": project,
        "scan": scan,
    }
    return render(request, "scanner/scan_detail.html", context)


@require_POST
def delete_scan(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    project_id = scan.project.id
    scan.delete()
    messages.success(request, "Scan deleted.")
    return redirect("project_detail", project_id=project_id)


def live_scan(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    return render(request, "scanner/live_scan.html", {"scan": scan})


@api_view(["GET"])
def live_feed(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    since = request.GET.get("since", "0")
    try:
        since_id = int(since)
    except ValueError:
        since_id = 0

    logs = ScanLog.objects.filter(scan=scan, id__gt=since_id).order_by("id")[:200]
    progress = None
    try:
        prog = scan.progress
        progress = {
            "step": prog.step, "step_index": prog.step_index, "step_total": prog.step_total,
            "message": prog.message, "subs_found": prog.subs_found,
            "subs_resolved": prog.subs_resolved, "subs_live": prog.subs_live,
            "ports_found": prog.ports_found, "nuclei_found": prog.nuclei_found,
            "secrets_found": prog.secrets_found, "endpoints_found": prog.endpoints_found,
        }
    except Exception:
        pass

    return Response({
        "status": scan.status,
        "progress": progress,
        "logs": [{"id": l.id, "category": l.category, "message": l.message, "data": l.data} for l in logs],
    })


def scan_partial(request, scan_id, tab):
    scan = get_object_or_404(Scan, id=scan_id)
    template_name = f"scanner/partials/scan_{tab}.html"
    context = {"scan": scan}

    if tab == "subdomains":
        context["subdomains"] = scan.subdomains.prefetch_related("ports").all()
    elif tab == "ports":
        context["ports"] = Port.objects.filter(
            subdomain__scan=scan
        ).select_related("subdomain").order_by("port_number")
    elif tab == "nuclei":
        context["findings"] = scan.nuclei_findings.all()
    elif tab == "dorks":
        context["dorks"] = scan.dorks.all()[:500]
    elif tab == "endpoints":
        context["scan"] = scan
    elif tab == "secrets":
        context["secrets"] = scan.secrets.all()
        context["keywords"] = Keyword.objects.filter(
            models.Q(project=scan.project) | models.Q(project__isnull=True)
        )
    elif tab == "jsfiles":
        context["js_files"] = scan.crawled_urls.filter(is_js=True)
        context["keywords"] = Keyword.objects.filter(
            models.Q(project=scan.project) | models.Q(project__isnull=True)
        )
    elif tab == "takeover":
        context["takeovers"] = scan.takeovers.all()
    elif tab == "s3":
        context["buckets"] = scan.s3_buckets.all()
    elif tab == "xss":
        context["findings"] = scan.xss_findings.all()
    elif tab == "overview":
        context["subdomains"] = scan.subdomains.prefetch_related("ports").all()[:20]
        context["findings"] = scan.nuclei_findings.order_by(
            "severity"
        )[:20]

    return render(request, template_name, context)


def diff_scans(request, project_id):
    project = get_object_or_404(Project, id=project_id)
    scans = project.scans.order_by("-created_at")

    scan_a_id = request.GET.get("scan_a")
    scan_b_id = request.GET.get("scan_b")

    context = {"project": project, "scans": scans}

    if scan_a_id and scan_b_id:
        scan_a = get_object_or_404(Scan, id=scan_a_id, project=project)
        scan_b = get_object_or_404(Scan, id=scan_b_id, project=project)
        diff = run_diff(scan_a, scan_b)
        context["scan_a"] = scan_a
        context["scan_b"] = scan_b
        context["diff"] = diff

    return render(request, "scanner/diff_scan.html", context)


# ── AJAX Endpoints ──


@api_view(["GET"])
def scan_status(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    progress = None
    try:
        p = scan.progress
        progress = {
            "step": p.step, "step_index": p.step_index, "step_total": p.step_total,
            "message": p.message, "subs_found": p.subs_found,
            "subs_resolved": p.subs_resolved, "subs_live": p.subs_live,
            "ports_found": p.ports_found, "nuclei_found": p.nuclei_found,
        }
    except Exception:
        pass
    return Response({
        "status": scan.status,
        "error": scan.error_message,
        "subdomain_count": scan.subdomain_count,
        "live_count": scan.live_count,
        "port_count": scan.port_count,
        "nuclei_finding_count": scan.nuclei_finding_count,
        "secret_count": scan.secret_count,
        "api_endpoint_count": scan.api_endpoint_count,
        "takeover_count": scan.takeover_count,
        "s3_bucket_count": scan.s3_bucket_count,
        "xss_finding_count": scan.xss_finding_count,
        "progress": progress,
    })


@api_view(["POST"])
def scan_subdomain_json(request, scan_id):
    scan = get_object_or_404(Scan, id=scan_id)
    subs = scan.subdomains.values("name", "ip", "http_status", "http_title", "technologies")
    return Response(list(subs))


@api_view(["GET"])
def js_file_content(request, url_id):
    url_obj = get_object_or_404(CrawledURL, id=url_id)
    content = ""
    local_path = url_obj.local_path
    if local_path and os.path.isfile(local_path):
        with open(local_path, errors="replace") as f:
            content = f.read()
    if not content and url_obj.scan.output_dir:
        js_name = os.path.basename(url_obj.url.split("?")[0])
        alt_path = os.path.join(url_obj.scan.output_dir, "linkgather", "js", f"{url_obj.subdomain}__{js_name}")
        if os.path.isfile(alt_path):
            with open(alt_path, errors="replace") as f:
                content = f.read()
    if not content:
        return Response({"error": "File not found", "url": url_obj.url}, status=404)
    return Response({"content": content, "url": url_obj.url})


def js_code_view(request, scan_id, url_id):
    scan = get_object_or_404(Scan, id=scan_id)
    js_file = get_object_or_404(CrawledURL, id=url_id, scan=scan)
    content = ""
    local_path = js_file.local_path
    if local_path and os.path.isfile(local_path):
        with open(local_path, errors="replace") as f:
            content = f.read()
    if not content and scan.output_dir:
        js_name = os.path.basename(js_file.url.split("?")[0])
        alt_path = os.path.join(scan.output_dir, "linkgather", "js", f"{js_file.subdomain}__{js_name}")
        if os.path.isfile(alt_path):
            with open(alt_path, errors="replace") as f:
                content = f.read()
    if not content:
        return HttpResponse(f"// File not found: {js_file.url}", content_type="text/plain")

    try:
        import jsbeautifier
        opts = jsbeautifier.default_options()
        opts.indent_size = 2
        opts.space_in_empty_paren = True
        content = jsbeautifier.beautify(content, opts)
    except Exception:
        pass

    keywords = Keyword.objects.filter(
        models.Q(project=scan.project) | models.Q(project__isnull=True)
    )
    kw_list = [{"keyword": kw.keyword, "category": kw.category} for kw in keywords]

    return render(request, "scanner/js_viewer.html", {
        "js_file": js_file,
        "js_url_name": os.path.basename(js_file.url.split("?")[0]),
        "js_content_json": json.dumps(content),
        "keywords": keywords,
        "keywords_json": json.dumps(kw_list),
    })


@api_view(["POST"])
def toggle_secret_verify(request, secret_id):
    secret = get_object_or_404(Secret, id=secret_id)
    secret.verified = not secret.verified
    secret.save()
    return Response({"verified": secret.verified})


def api_docs(request):
    endpoints = [
        {"method": "GET", "path": "/api/projects/", "desc": "List all projects"},
        {"method": "POST", "path": "/api/projects/", "desc": "Create a new project", "body": '{"name":"Name","domain":"example.com","notes":"optional"}'},
        {"method": "GET", "path": "/api/projects/{id}/", "desc": "Get project detail"},
        {"method": "PUT", "path": "/api/projects/{id}/", "desc": "Update project"},
        {"method": "DELETE", "path": "/api/projects/{id}/", "desc": "Delete project"},
        {"method": "POST", "path": "/api/projects/{id}/scan/", "desc": "Start a new scan for project (async)"},
        {"method": "GET", "path": "/api/projects/{id}/diff/?scan_a=X&scan_b=Y", "desc": "Diff two scans"},
        {"method": "GET", "path": "/api/scans/", "desc": "List all scans", "params": "?project=ID&status=completed"},
        {"method": "GET", "path": "/api/scans/{id}/", "desc": "Get scan detail (includes counts)"},
        {"method": "GET", "path": "/api/scans/{id}/subdomains/", "desc": "All subdomains for scan", "params": "?resolved=true"},
        {"method": "GET", "path": "/api/scans/{id}/ports/", "desc": "All ports for scan"},
        {"method": "GET", "path": "/api/scans/{id}/nuclei/", "desc": "Nuclei findings", "params": "?severity=critical"},
        {"method": "GET", "path": "/api/scans/{id}/secrets/", "desc": "Secrets found"},
        {"method": "GET", "path": "/api/scans/{id}/endpoints/", "desc": "API endpoints"},
        {"method": "GET", "path": "/api/scans/{id}/takeover/", "desc": "Takeover checks", "params": "?vulnerable=true"},
        {"method": "GET", "path": "/api/scans/{id}/s3/", "desc": "S3 buckets found"},
        {"method": "GET", "path": "/api/scans/{id}/xss/", "desc": "XSS findings"},
        {"method": "GET", "path": "/api/scans/{id}/dorks/", "desc": "Google dorks"},
        {"method": "GET", "path": "/api/scans/{id}/status/", "desc": "Get scan status only"},
        {"method": "GET", "path": "/api/subdomains/", "desc": "All subdomains across scans", "params": "?name=admin&scan=ID"},
        {"method": "GET", "path": "/api/nuclei/", "desc": "Nuclei findings across scans", "params": "?severity=critical"},
        {"method": "GET", "path": "/api/ports/", "desc": "Ports across scans"},
        {"method": "GET", "path": "/api/keywords/", "desc": "List keyword patterns for JS highlighting"},
        {"method": "POST", "path": "/api/keywords/", "desc": "Create keyword", "body": '{"name":"eval","keyword":"eval","category":"sink"}'},
        {"method": "POST", "path": "/api/scan/{secret_id}/toggle-verify/", "desc": "Toggle secret verified status"},
        {"method": "GET", "path": "/api/scan/js-content/{url_id}/", "desc": "Get JS file content for code viewer"},
    ]
    return render(request, "scanner/api_docs.html", {"endpoints": endpoints})


# ── REST API ViewSets ──


class ProjectViewSet(viewsets.ModelViewSet):
    queryset = Project.objects.all()
    serializer_class = ProjectSerializer

    @action(detail=True, methods=["post"])
    def scan(self, request, pk=None):
        project = self.get_object()
        today = timezone.now().date()
        existing = Scan.objects.filter(project=project, scan_date=today).first()
        if existing:
            return Response(
                {"error": "Scan for today already exists", "scan_id": existing.id},
                status=status.HTTP_409_CONFLICT,
            )
        scan = Scan.objects.create(project=project, scan_date=today, status="pending")
        task = run_scan_pipeline.delay(scan.id)
        scan.task_id = task.id
        scan.save(update_fields=["task_id"])
        return Response(ScanSerializer(scan).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["get"])
    def diff(self, request, pk=None):
        project = self.get_object()
        scan_a_id = request.query_params.get("scan_a")
        scan_b_id = request.query_params.get("scan_b")
        if not scan_a_id or not scan_b_id:
            return Response(
                {"error": "scan_a and scan_b query params required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        scan_a = get_object_or_404(Scan, id=scan_a_id, project=project)
        scan_b = get_object_or_404(Scan, id=scan_b_id, project=project)
        diff = run_diff(scan_a, scan_b)
        return Response(diff)


class ScanViewSet(viewsets.ModelViewSet):
    queryset = Scan.objects.all()
    serializer_class = ScanSerializer

    @action(detail=True, methods=["get"])
    def subdomains(self, request, pk=None):
        scan = self.get_object()
        subs = scan.subdomains.all()
        page = self.paginate_queryset(subs)
        if page is not None:
            return self.get_paginated_response(SubdomainSerializer(page, many=True).data)
        return Response(SubdomainSerializer(subs, many=True).data)

    @action(detail=True, methods=["get"])
    def ports(self, request, pk=None):
        scan = self.get_object()
        ports = Port.objects.filter(subdomain__scan=scan).select_related("subdomain")
        page = self.paginate_queryset(ports)
        if page is not None:
            return self.get_paginated_response(PortSerializer(page, many=True).data)
        return Response(PortSerializer(ports, many=True).data)

    @action(detail=True, methods=["get"])
    def nuclei(self, request, pk=None):
        scan = self.get_object()
        findings = scan.nuclei_findings.all()
        page = self.paginate_queryset(findings)
        if page is not None:
            return self.get_paginated_response(NucleiFindingSerializer(page, many=True).data)
        return Response(NucleiFindingSerializer(findings, many=True).data)

    @action(detail=True, methods=["get"])
    def endpoints(self, request, pk=None):
        scan = self.get_object()
        qs = scan.api_endpoints.all()
        return Response(APIEndpointSerializer(qs, many=True).data)

    @action(detail=True, methods=["get"])
    def secrets(self, request, pk=None):
        scan = self.get_object()
        qs = scan.secrets.all()
        return Response(SecretSerializer(qs, many=True).data)

    @action(detail=True, methods=["get"])
    def takeover(self, request, pk=None):
        scan = self.get_object()
        qs = scan.takeovers.all()
        return Response(TakeoverSerializer(qs, many=True).data)

    @action(detail=True, methods=["get"])
    def s3(self, request, pk=None):
        scan = self.get_object()
        qs = scan.s3_buckets.all()
        return Response(S3BucketSerializer(qs, many=True).data)

    @action(detail=True, methods=["get"])
    def xss(self, request, pk=None):
        scan = self.get_object()
        qs = scan.xss_findings.all()
        return Response(XSSFindingSerializer(qs, many=True).data)

    @action(detail=True, methods=["get"])
    def dorks(self, request, pk=None):
        scan = self.get_object()
        qs = scan.dorks.all()[:500]
        return Response(DorkSerializer(qs, many=True).data)

    @action(detail=True, methods=["get"])
    def status(self, request, pk=None):
        scan = self.get_object()
        return Response(ScanSerializer(scan).data)

    @action(detail=True, methods=["post"], url_path=r"nuclei-sub/(?P<subdomain_id>\d+)")
    def nuclei_subdomain(self, request, pk=None, subdomain_id=None):
        scan = self.get_object()
        try:
            subdomain = Subdomain.objects.get(id=subdomain_id, scan=scan)
        except Subdomain.DoesNotExist:
            return Response({"error": "Subdomain not found"}, status=404)
        ports = list(subdomain.ports.values_list("port_number", flat=True))
        if not ports:
            return Response({"error": "No open ports for this subdomain"}, status=400)
        from .tasks import run_single_nuclei
        run_single_nuclei.delay(scan.id, subdomain.id, ports)
        return Response({
             "status": "started",
            "subdomain": subdomain.name,
            "targets": len(ports),
        })

    @action(detail=True, methods=["get"], url_path=r"nuclei-sub/(?P<subdomain_id>\d+)/status")
    def nuclei_sub_status(self, request, pk=None, subdomain_id=None):
        scan = self.get_object()
        try:
            subdomain = Subdomain.objects.get(id=subdomain_id, scan=scan)
        except Subdomain.DoesNotExist:
            return Response({"error": "Subdomain not found"}, status=404)

        from .models import ScanLog
        started = ScanLog.objects.filter(
            scan=scan, category="nuclei_start",
            data__subdomain_id=subdomain_id,
        ).order_by("-id").first()
        done = ScanLog.objects.filter(
            scan=scan, category="nuclei_done",
            data__subdomain_id=subdomain_id,
        ).order_by("-id").first()

        running = started and not done
        findings = done.data.get("findings", 0) if done else 0

        logs = list(ScanLog.objects.filter(
            scan=scan, category__in=["nuclei_start", "nuclei_done", "output"],
        ).filter(
            Q(data__subdomain_id=subdomain_id) | Q(message__icontains=subdomain.name)
        ).order_by("-id")[:20])

        return Response({
            "running": running,
            "findings": findings,
            "subdomain": subdomain.name,
            "logs": [{"msg": l.message, "cat": l.category} for l in reversed(logs)],
        })


class SubdomainViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Subdomain.objects.all()
    serializer_class = SubdomainSerializer


class NucleiFindingViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = NucleiFinding.objects.all()
    serializer_class = NucleiFindingSerializer


class PortViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Port.objects.all()
    serializer_class = PortSerializer


class KeywordViewSet(viewsets.ModelViewSet):
    queryset = Keyword.objects.all()
    serializer_class = KeywordSerializer


# ── Organisation Views ──

def org_list(request):
    if request.method == "POST":
        name = request.POST.get("name", "").strip()
        if name:
            Organisation.objects.get_or_create(name=name)
            messages.success(request, f"Created organisation: {name}")
        return redirect("org_list")
    orgs = Organisation.objects.annotate(
        project_count=Count("projects")
    ).order_by("-created_at")
    return render(request, "scanner/org_list.html", {"orgs": orgs})


def org_detail(request, org_id):
    org = get_object_or_404(Organisation, id=org_id)
    projects = org.projects.annotate(scan_count=Count("scans")).order_by("-created_at")
    cidrs = org.cidrs.all()
    # Discovered domains not yet added as projects
    existing_domains = set(projects.values_list("domain", flat=True))
    discovered = set()
    for cidr in cidrs:
        for d in cidr.discovered_domains:
            if d not in existing_domains:
                discovered.add(d)
    return render(request, "scanner/org_detail.html", {
        "org": org, "projects": projects, "cidrs": cidrs,
        "discovered_domains": sorted(discovered),
    })


@require_POST
def org_start_asn(request, org_id):
    org = get_object_or_404(Organisation, id=org_id)
    if org.asn_status == "running":
        messages.warning(request, "ASN scan already running")
        return redirect("org_detail", org_id=org.id)
    org.asn_status = "running"
    org.save()
    run_org_asn_discovery.delay(org.id)
    messages.success(request, f"ASN discovery started for {org.name}")
    return redirect("org_detail", org_id=org.id)


@require_POST
def org_delete(request, org_id):
    org = get_object_or_404(Organisation, id=org_id)
    name = org.name
    org.delete()
    messages.success(request, f"Deleted organisation: {name}")
    return redirect("org_list")


@require_POST
def org_add_domain(request, org_id):
    org = get_object_or_404(Organisation, id=org_id)
    domain = request.POST.get("domain", "").strip().lower()
    if not domain:
        messages.error(request, "Domain required")
        return redirect("org_detail", org_id=org.id)
    project, created = Project.objects.get_or_create(
        domain=domain,
        defaults={"name": domain, "organisation": org},
    )
    if created:
        messages.success(request, f"Added {domain} as project")
    else:
        project.organisation = org
        project.save()
        messages.info(request, f"{domain} linked to {org.name}")
    return redirect("org_detail", org_id=org.id)


@require_POST
def org_import_discovered(request, org_id):
    org = get_object_or_404(Organisation, id=org_id)
    existing = set(org.projects.values_list("domain", flat=True))
    added = 0
    for cidr in org.cidrs.all():
        for d in cidr.discovered_domains:
            if d not in existing:
                Project.objects.get_or_create(
                    domain=d,
                    defaults={"name": d, "organisation": org},
                )
                existing.add(d)
                added += 1
    messages.success(request, f"Added {added} discovered domains as projects")
    return redirect("org_detail", org_id=org.id)


def org_live_feed(request, org_id):
    org = get_object_or_404(Organisation, id=org_id)
    since = request.GET.get("since", "0")
    try:
        since_id = int(since)
    except ValueError:
        since_id = 0
    logs = ScanLog.objects.filter(scan__isnull=True, id__gt=since_id).order_by("id")[:200]
    return JsonResponse({
        "status": org.asn_status,
        "cidr_count": org.asn_cidr_count,
        "ip_count": org.asn_ip_count,
        "domain_count": org.asn_domain_count,
        "logs": [{"id": l.id, "category": l.category, "message": l.message} for l in logs],
    })

class OrganisationViewSet(viewsets.ModelViewSet):
    queryset = Organisation.objects.all()
    serializer_class = OrganisationSerializer

    @action(detail=True, methods=["post"])
    def asn_scan(self, request, pk=None):
        org = self.get_object()
        if org.asn_status == "running":
            return Response({"error": "ASN scan already running"}, status=409)
        org.asn_status = "running"
        org.save()
        run_org_asn_discovery.delay(org.id)
        return Response({"status": "started"})
