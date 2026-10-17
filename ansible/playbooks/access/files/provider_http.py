"""Provider credentials must never follow HTTP redirects to another endpoint."""
import urllib.request


class RejectRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(RejectRedirect())


def open_request(request, timeout=30):
    return _OPENER.open(request, timeout=timeout)
