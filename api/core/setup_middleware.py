"""SetupGateMiddleware — blocks all endpoints until first-run setup is complete.

Only allows:
  - /api/setup/*   (setup wizard endpoints)
  - /health/       (health check)
  - OPTIONS         (CORS preflight)
"""

import logging

from django.http import JsonResponse

logger = logging.getLogger('bytescop.setup')

ALLOWED_PREFIXES = ('/api/setup/', '/api/health/', '/health/', '/api/tenant/close/status/')


class SetupGateMiddleware:
    """Blocks all requests until InstallState.installed is True."""

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Allow CORS preflight
        if request.method == 'OPTIONS':
            return self.get_response(request)

        # Allow setup and health endpoints
        if any(request.path.startswith(p) for p in ALLOWED_PREFIXES):
            return self.get_response(request)

        # Check install state (no cache — allows reset after last tenant deletion)
        if not self._is_installed():
            return JsonResponse(
                {
                    'setup_required': True,
                    'detail': 'BytesCop-Reporter has not been configured yet. Please complete the setup wizard to get started.',
                },
                status=403,
            )

        return self.get_response(request)

    def _is_installed(self) -> bool:
        try:
            from core.models import InstallState
            state = InstallState.objects.filter(id=1).first()
            return bool(state and state.installed)
        except Exception:
            # Table might not exist yet (pre-migration)
            return False
