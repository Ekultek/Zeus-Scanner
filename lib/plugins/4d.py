import re

import lib.core.common


__product__ = "4D"
__description__ = (
    "4D web application deployment server"
)


def search(html, **kwargs):
    headers = kwargs.get("headers", None)
    plugin_detection_schema = (
        re.compile(r"/^4D_v[\d]{1,2}(_SQL)?\/([\d\.]+)$/", re.I),
    )
    for plugin in plugin_detection_schema:
        if plugin.search(headers.get(lib.core.common.HTTP_HEADER.SERVER, "")) is not None:
            return True
