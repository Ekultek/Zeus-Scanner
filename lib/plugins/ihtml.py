import re

import lib.core.common


__product__ = "iHTML"
__description__ = (
    "iHTML is a server side internet/web programming and scripting "
    "language in used by thousands of sites worldwide to deliver "
    "cost effective dynamic database driven web sites"
)


def search(html, **kwargs):
    html = str(html)
    headers = kwargs.get("headers", None)
    plugin_detection_schema = (
        re.compile(r".ihtml.", re.I),
        re.compile(r"\bihtml.", re.I)
    )
    for plugin in plugin_detection_schema:
        if plugin.search(html) is not None:
            return True
        if plugin.search(headers.get(lib.core.common.HTTP_HEADER.X_POWERED_BY, "")) is not None:
            return True
