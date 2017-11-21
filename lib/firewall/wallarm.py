import re

from lib.core.common import HTTP_HEADER


__item__ = "Wallarm Web Application Firewall (Wallarm)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"nginx-wallarm", re.I),
    )
    for detection in detection_schema:
        if detection.search(headers.get(HTTP_HEADER.SERVER, "")) is not None:
            return True
