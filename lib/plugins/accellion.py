import re

import lib.core.common


__product__ = "Accellion-Secure-File-Transfer"
__description__ = (
    "Accellion Secure File Transfer (SFT)"
)


def search(html, **kwargs):
    headers = kwargs.get("headers", None)
    plugin_detection_schema = (
        re.compile(r"/sfcurl.deleted./", re.I),
        re.compile(r"/\/courier\/[\d]+@\/mail_user_login\.html\?$/", re.I),
    )
    for plugin in plugin_detection_schema:
        if plugin.search(headers.get(lib.core.common.HTTP_HEADER.LOCATION, "")) is not None:
            return True
        if plugin.search(headers.get(lib.core.common.HTTP_HEADER.SET_COOKIE, "")) is not None:
            return True
