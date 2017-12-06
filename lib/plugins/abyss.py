import re

import lib.core.common


__product__ = "Abyss-Web-Server"
__description__ = (
    "Abyss Web Server is a compact web server available "
    "for Windows, Mac OS X, Linux, and FreeBSD operating systems"
)


def search(html, **kwargs):
    headers = kwargs.get("headers", None)
    plugin_detection_schema = (
        re.compile(r"/^Abyss\/([^\s]+)/", re.I),
    )
    for plugin in plugin_detection_schema:
        if plugin.search(headers.get(lib.core.common.HTTP_HEADER.SERVER, "")) is not None:
            return True
