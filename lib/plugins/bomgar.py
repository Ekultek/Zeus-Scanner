import re

import lib.core.common


__product__ = "Bomgar"
__description__ = (
    "Bomgar simplifies support by letting technicians control "
    "remote computers, servers, smartphones and network devices "
    "over the internet or network. With Bomgar, a support rep can "
    "see what customers see or control their computers for support"
)


def search(html, **kwargs):
    html = str(html)
    headers = kwargs.get("headers", None)
    plugin_detection_schema = (
        re.compile(".bomgar.", re.I),
        re.compile(r"http(s)?.//(www.)?bomgar.com", re.I),
        re.compile(r"alt.[\'\"]?remote.support.by.bomgar[\'\"]?", re.I)
    )
    for plugin in plugin_detection_schema:
        if plugin.search(headers.get(lib.core.common.HTTP_HEADER.SERVER, "")) is not None:
            return True
        if plugin.search(html) is not None:
            return True
