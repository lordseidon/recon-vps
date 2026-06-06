from django.contrib import admin
from .models import (
    Project, Scan, Subdomain, Port, NucleiFinding,
    Dork, CrawledURL, APIEndpoint, Secret, S3Bucket,
    Takeover, XSSFinding, Keyword,
)


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ["name", "domain", "created_at"]
    search_fields = ["name", "domain"]


@admin.register(Scan)
class ScanAdmin(admin.ModelAdmin):
    list_display = ["project", "scan_date", "status", "subdomain_count", "nuclei_finding_count", "created_at"]
    list_filter = ["status", "project"]
    search_fields = ["project__domain"]


@admin.register(Subdomain)
class SubdomainAdmin(admin.ModelAdmin):
    list_display = ["name", "ip", "resolved", "http_status", "scan"]
    list_filter = ["resolved", "http_status"]


@admin.register(Port)
class PortAdmin(admin.ModelAdmin):
    list_display = ["subdomain", "port_number"]
    search_fields = ["subdomain__name"]


@admin.register(NucleiFinding)
class NucleiFindingAdmin(admin.ModelAdmin):
    list_display = ["template_id", "severity", "matched_at", "scan"]
    list_filter = ["severity"]


@admin.register(Dork)
class DorkAdmin(admin.ModelAdmin):
    list_display = ["subdomain_name", "dork_type", "scan"]


@admin.register(CrawledURL)
class CrawledURLAdmin(admin.ModelAdmin):
    list_display = ["subdomain", "url", "is_js", "is_api", "scan"]


@admin.register(APIEndpoint)
class APIEndpointAdmin(admin.ModelAdmin):
    list_display = ["url", "subdomain", "source", "scan"]


@admin.register(Secret)
class SecretAdmin(admin.ModelAdmin):
    list_display = ["detector_name", "verified", "file_path", "scan"]
    list_filter = ["verified"]


@admin.register(S3Bucket)
class S3BucketAdmin(admin.ModelAdmin):
    list_display = ["bucket_name", "is_open", "scan"]


@admin.register(Takeover)
class TakeoverAdmin(admin.ModelAdmin):
    list_display = ["subdomain_name", "vulnerable", "service", "scan"]
    list_filter = ["vulnerable"]


@admin.register(XSSFinding)
class XSSFindingAdmin(admin.ModelAdmin):
    list_display = ["url", "scan"]


@admin.register(Keyword)
class KeywordAdmin(admin.ModelAdmin):
    list_display = ["name", "keyword", "category", "project"]
    list_filter = ["category"]
