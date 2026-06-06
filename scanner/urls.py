from django.urls import path, include
from rest_framework.routers import DefaultRouter

from . import views

router = DefaultRouter()
router.register(r"projects", views.ProjectViewSet)
router.register(r"scans", views.ScanViewSet)
router.register(r"subdomains", views.SubdomainViewSet)
router.register(r"nuclei", views.NucleiFindingViewSet)
router.register(r"ports", views.PortViewSet)
router.register(r"keywords", views.KeywordViewSet)
router.register(r"organisations", views.OrganisationViewSet)

urlpatterns = [
    path("", views.org_list, name="dashboard"),
    path("projects/", views.projects_list, name="projects_list"),
    path("orgs/", views.org_list, name="org_list"),
    path("org/<int:org_id>/", views.org_detail, name="org_detail"),
    path("org/<int:org_id>/start-asn/", views.org_start_asn, name="org_start_asn"),
    path("org/<int:org_id>/add-domain/", views.org_add_domain, name="org_add_domain"),
    path("org/<int:org_id>/import-discovered/", views.org_import_discovered, name="org_import_discovered"),
    path("org/<int:org_id>/delete/", views.org_delete, name="org_delete"),
    path("org/<int:org_id>/live/feed/", views.org_live_feed, name="org_live_feed"),
    path("docs/", views.api_docs, name="api_docs"),
    path("project/<int:project_id>/", views.project_detail, name="project_detail"),
    path("project/<int:project_id>/start-scan/", views.start_scan, name="start_scan"),
    path("project/<int:project_id>/test-dns/", views.test_dns, name="test_dns"),
    path("project/<int:project_id>/delete/", views.delete_project, name="delete_project"),
    path("project/<int:project_id>/diff/", views.diff_scans, name="diff_scans"),
    path("scan/<int:scan_id>/", views.scan_detail, name="scan_detail"),
    path("scan/<int:scan_id>/status/", views.scan_status, name="scan_status"),
    path("scan/<int:scan_id>/subs-json/", views.scan_subdomain_json, name="scan_subdomain_json"),
    path("scan/<int:scan_id>/partial/<str:tab>/", views.scan_partial, name="scan_partial"),
    path("api/scan/<int:secret_id>/toggle-verify/", views.toggle_secret_verify, name="toggle_secret_verify"),
    path("api/scan/js-content/<int:url_id>/", views.js_file_content, name="js_file_content"),
    path("scan/<int:scan_id>/delete/", views.delete_scan, name="delete_scan"),
    path("scan/<int:scan_id>/live/", views.live_scan, name="live_scan"),
    path("scan/<int:scan_id>/live/feed/", views.live_feed, name="live_feed"),
    path("api/", include(router.urls)),
]
