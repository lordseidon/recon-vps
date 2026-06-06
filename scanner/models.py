import uuid
from django.db import models
from django.utils import timezone


class Organisation(models.Model):
    name = models.CharField(max_length=255, unique=True)
    slug = models.CharField(max_length=255, unique=True, blank=True)
    notes = models.TextField(blank=True, default="")
    asn_status = models.CharField(max_length=20, default="idle")
    asn_cidr_count = models.IntegerField(default=0)
    asn_ip_count = models.IntegerField(default=0)
    asn_domain_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def save(self, *args, **kwargs):
        if not self.slug:
            import re
            self.slug = re.sub(r'[^a-z0-9]+', '-', self.name.lower()).strip('-')
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name

    @property
    def domain_count(self):
        return self.projects.count()

    @property
    def total_subdomains(self):
        from django.db.models import Sum
        return self.projects.aggregate(s=Sum('scans__subdomain_count'))['s'] or 0


class ASNCIDR(models.Model):
    organisation = models.ForeignKey(Organisation, on_delete=models.CASCADE, related_name="cidrs")
    cidr = models.CharField(max_length=64)
    open_ips = models.JSONField(default=list, blank=True)
    discovered_domains = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ["cidr"]
        unique_together = ["organisation", "cidr"]

    def __str__(self):
        return self.cidr


class Project(models.Model):
    organisation = models.ForeignKey(Organisation, on_delete=models.SET_NULL, null=True, blank=True, related_name="projects")
    name = models.CharField(max_length=255)
    domain = models.CharField(max_length=255, unique=True)
    notes = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.name} ({self.domain})"

    @property
    def latest_scan(self):
        return self.scans.order_by("-created_at").first()


class Scan(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("running", "Running"),
        ("completed", "Completed"),
        ("failed", "Failed"),
    ]

    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="scans")
    scan_date = models.DateField(default=timezone.now)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default="pending")
    output_dir = models.CharField(max_length=512, blank=True, default="")
    error_message = models.TextField(blank=True, default="")
    task_id = models.CharField(max_length=255, blank=True, default="")

    subdomain_count = models.IntegerField(default=0)
    resolved_count = models.IntegerField(default=0)
    live_count = models.IntegerField(default=0)
    port_count = models.IntegerField(default=0)
    nuclei_finding_count = models.IntegerField(default=0)
    secret_count = models.IntegerField(default=0)
    api_endpoint_count = models.IntegerField(default=0)
    takeover_count = models.IntegerField(default=0)
    s3_bucket_count = models.IntegerField(default=0)
    xss_finding_count = models.IntegerField(default=0)

    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]
        unique_together = ["project", "scan_date"]

    def __str__(self):
        return f"{self.project.domain} — {self.scan_date}"

    @property
    def version_label(self):
        return self.scan_date.strftime("%d-%m-%Y")


class Subdomain(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="subdomains")
    name = models.CharField(max_length=512)
    ip = models.CharField(max_length=45, blank=True, default="")
    record_type = models.CharField(max_length=10, blank=True, default="A")
    resolved = models.BooleanField(default=False)
    http_url = models.CharField(max_length=1024, blank=True, default="")
    http_status = models.IntegerField(null=True, blank=True)
    http_title = models.CharField(max_length=1024, blank=True, default="")
    technologies = models.JSONField(default=list, blank=True)
    sources = models.JSONField(default=list, blank=True)

    class Meta:
        ordering = ["-resolved", "name"]
        indexes = [
            models.Index(fields=["scan", "name"]),
            models.Index(fields=["scan", "resolved"]),
        ]

    def __str__(self):
        return self.name


class Port(models.Model):
    subdomain = models.ForeignKey(Subdomain, on_delete=models.CASCADE, related_name="ports")
    port_number = models.IntegerField()
    protocol = models.CharField(max_length=10, blank=True, default="tcp")
    service = models.CharField(max_length=255, blank=True, default="")

    class Meta:
        ordering = ["port_number"]
        unique_together = ["subdomain", "port_number"]

    def __str__(self):
        return f"{self.subdomain.name}:{self.port_number}"


class NucleiFinding(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="nuclei_findings")
    template_id = models.CharField(max_length=512)
    name = models.CharField(max_length=512)
    severity = models.CharField(max_length=50)
    matched_at = models.CharField(max_length=2048)
    extracted_results = models.TextField(blank=True, default="")
    curl_command = models.TextField(blank=True, default="")
    host = models.CharField(max_length=512, blank=True, default="")
    ip = models.CharField(max_length=45, blank=True, default="")
    raw_data = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["severity", "template_id"]

    def __str__(self):
        return f"[{self.severity}] {self.template_id} @ {self.matched_at}"

    @property
    def severity_class(self):
        return {
            "critical": "danger", "high": "warning", "medium": "info-medium",
            "low": "success", "info": "info", "unknown": "secondary",
        }.get(self.severity.lower(), "secondary")


class Dork(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="dorks")
    subdomain_name = models.CharField(max_length=512)
    dork_type = models.CharField(max_length=255)
    query = models.TextField()

    class Meta:
        ordering = ["subdomain_name", "dork_type"]
        indexes = [models.Index(fields=["scan", "subdomain_name"])]

    def __str__(self):
        return f"{self.subdomain_name}: {self.dork_type}"


class CrawledURL(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="crawled_urls")
    subdomain = models.CharField(max_length=512)
    url = models.TextField()
    is_js = models.BooleanField(default=False)
    is_api = models.BooleanField(default=False)
    local_path = models.CharField(max_length=1024, blank=True, default="")

    class Meta:
        ordering = ["subdomain", "url"]
        indexes = [models.Index(fields=["scan", "subdomain"])]

    def __str__(self):
        return f"{self.subdomain}: {self.url[:80]}"


class APIEndpoint(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="api_endpoints")
    subdomain = models.CharField(max_length=512, blank=True, default="")
    url = models.TextField()
    source = models.CharField(max_length=255, blank=True, default="")

    class Meta:
        ordering = ["subdomain", "url"]

    def __str__(self):
        return self.url


class Secret(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="secrets")
    detector_name = models.CharField(max_length=512)
    verified = models.BooleanField(default=False)
    raw = models.TextField(blank=True, default="")
    raw_v2 = models.TextField(blank=True, default="")
    file_path = models.CharField(max_length=1024, blank=True, default="")
    source_metadata = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-verified", "detector_name"]

    def __str__(self):
        return f"{self.detector_name}"


class S3Bucket(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="s3_buckets")
    bucket_name = models.CharField(max_length=512)
    is_open = models.BooleanField(default=False)
    contents = models.TextField(blank=True, default="")

    class Meta:
        ordering = ["bucket_name"]

    def __str__(self):
        return self.bucket_name


class Takeover(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="takeovers")
    subdomain_name = models.CharField(max_length=512)
    vulnerable = models.BooleanField(default=False)
    service = models.CharField(max_length=255, blank=True, default="")

    class Meta:
        ordering = ["-vulnerable", "subdomain_name"]

    def __str__(self):
        v = "VULN" if self.vulnerable else "SAFE"
        return f"[{v}] {self.subdomain_name}"


class XSSFinding(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="xss_findings")
    url = models.TextField()
    poc = models.TextField(blank=True, default="")

    def __str__(self):
        return f"XSS @ {self.url[:80]}"


class Keyword(models.Model):
    CATEGORY_CHOICES = [
        ("sink", "Sink"),
        ("source", "Source"),
        ("both", "Both"),
    ]
    name = models.CharField(max_length=255)
    keyword = models.CharField(max_length=255)
    category = models.CharField(max_length=10, choices=CATEGORY_CHOICES, default="sink")
    project = models.ForeignKey(Project, on_delete=models.CASCADE, related_name="keywords", null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["category", "name"]

    def __str__(self):
        return f"[{self.category}] {self.keyword}"


class DiffResult(models.Model):
    name = models.CharField(max_length=255)
    scan_a = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="diffs_a")
    scan_b = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="diffs_b")
    category = models.CharField(max_length=50)
    added = models.JSONField(default=list)
    removed = models.JSONField(default=list)
    changed = models.JSONField(default=list)
    summary = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"Diff: {self.name}"


class ScanLog(models.Model):
    scan = models.ForeignKey(Scan, on_delete=models.CASCADE, related_name="logs", null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)
    category = models.CharField(max_length=50, default="info")
    message = models.TextField()
    data = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["timestamp"]

    def __str__(self):
        return f"[{self.category}] {self.message[:80]}"


class ScanProgress(models.Model):
    scan = models.OneToOneField(Scan, on_delete=models.CASCADE, related_name="progress")
    step = models.CharField(max_length=100, default="idle")
    step_index = models.IntegerField(default=0)
    step_total = models.IntegerField(default=9)
    message = models.CharField(max_length=512, blank=True, default="")
    subs_found = models.IntegerField(default=0)
    subs_resolved = models.IntegerField(default=0)
    subs_live = models.IntegerField(default=0)
    ports_found = models.IntegerField(default=0)
    nuclei_found = models.IntegerField(default=0)
    secrets_found = models.IntegerField(default=0)
    endpoints_found = models.IntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Progress: {self.step} ({self.step_index}/{self.step_total})"
