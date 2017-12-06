import re

import lib.core.common


__product__ = "3dcart"
__description__ = (
    "The 3dcart Shopping Cart Software is a complete e-commerce solution for anyone."
)


def search(html, **kwargs):
    html = str(html)
    headers = kwargs.get("headers", None)
    plugin_detection_schema = (
        re.compile(r"3dcart.stats", re.I),
        re.compile(r"/3dvisit/", re.I)
    )
    for plugin in plugin_detection_schema:
        if plugin.search(html) is not None:
            return True
        if plugin.search(headers.get(lib.core.common.HTTP_HEADER.SET_COOKIE, "")) is not None:
            return True
