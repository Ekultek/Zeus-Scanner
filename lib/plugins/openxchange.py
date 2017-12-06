import re

import lib.core.common


__product__ = "Open-Xchange-Server"
__description__ = (
    "Open Xchange Mail Server"
)


def search(html, **kwargs):
    html = str(html)
    headers = kwargs.get("headers", None)
    plugin_detection_schema = (
        re.compile(r"open.xchange.server", re.I),
        re.compile(r"javascript.to.access.the.open.xchange.server", re.I),
        re.compile(r"/^http(s)?://(www.)?[^\/]+\/ox6\/ox\.html$/", re.I)
    )
    for plugin in plugin_detection_schema:
        if plugin.search(html) is not None:
            return True
        if plugin.search(headers.get(lib.core.common.HTTP_HEADER.LOCATION, "")) is not None:
            return True
