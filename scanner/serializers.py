from rest_framework import serializers
from .models import (
    Project, Scan, Subdomain, Port, NucleiFinding,
    Dork, CrawledURL, APIEndpoint, Secret, S3Bucket,
    Takeover, XSSFinding, DiffResult, Keyword,
    Organisation,
)


class ProjectSerializer(serializers.ModelSerializer):
    latest_scan_date = serializers.SerializerMethodField()
    scan_count = serializers.SerializerMethodField()

    class Meta:
        model = Project
        fields = "__all__"

    def get_latest_scan_date(self, obj):
        ls = obj.latest_scan
        return ls.scan_date.isoformat() if ls else None

    def get_scan_count(self, obj):
        return obj.scans.count()


class ScanSerializer(serializers.ModelSerializer):
    project_domain = serializers.ReadOnlyField(source="project.domain")
    project_name = serializers.ReadOnlyField(source="project.name")

    class Meta:
        model = Scan
        fields = "__all__"


class SubdomainSerializer(serializers.ModelSerializer):
    ports = serializers.SerializerMethodField()

    class Meta:
        model = Subdomain
        fields = "__all__"

    def get_ports(self, obj):
        return list(obj.ports.values_list("port_number", flat=True).order_by("port_number"))


class SubdomainListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Subdomain
        fields = ["id", "name", "ip", "http_status", "http_title", "technologies"]


class PortSerializer(serializers.ModelSerializer):
    subdomain_name = serializers.ReadOnlyField(source="subdomain.name")

    class Meta:
        model = Port
        fields = "__all__"


class NucleiFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = NucleiFinding
        fields = "__all__"


class DorkSerializer(serializers.ModelSerializer):
    class Meta:
        model = Dork
        fields = "__all__"


class APIEndpointSerializer(serializers.ModelSerializer):
    class Meta:
        model = APIEndpoint
        fields = "__all__"


class CrawledURLSerializer(serializers.ModelSerializer):
    class Meta:
        model = CrawledURL
        fields = "__all__"


class SecretSerializer(serializers.ModelSerializer):
    class Meta:
        model = Secret
        fields = "__all__"


class S3BucketSerializer(serializers.ModelSerializer):
    class Meta:
        model = S3Bucket
        fields = "__all__"


class TakeoverSerializer(serializers.ModelSerializer):
    class Meta:
        model = Takeover
        fields = "__all__"


class XSSFindingSerializer(serializers.ModelSerializer):
    class Meta:
        model = XSSFinding
        fields = "__all__"


class DiffResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = DiffResult
        fields = "__all__"


class ScanCompareSerializer(serializers.Serializer):
    scan_a_id = serializers.IntegerField()
    scan_b_id = serializers.IntegerField()

class KeywordSerializer(serializers.ModelSerializer):
    class Meta:
        model = Keyword
        fields = "__all__"

class OrganisationSerializer(serializers.ModelSerializer):
    domain_count = serializers.SerializerMethodField()
    class Meta:
        model = Organisation
        fields = "__all__"
    def get_domain_count(self, obj):
        return obj.projects.count()
