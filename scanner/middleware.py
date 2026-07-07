from django.shortcuts import redirect
from django.conf import settings
from django.http import JsonResponse


class LoginRequiredMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.exempt_paths = {
            settings.LOGIN_URL,
            "/logout/",
            "/admin/login/",
            "/admin/",
        }

    def __call__(self, request):
        if not request.user.is_authenticated:
            path = request.path
            if path in self.exempt_paths:
                pass
            elif path.startswith("/admin/"):
                pass
            elif path.startswith("/static/"):
                pass
            elif path.startswith("/api/"):
                return JsonResponse({"error": "Authentication required"}, status=401)
            else:
                return redirect(f"{settings.LOGIN_URL}?next={request.path}")
        return self.get_response(request)
