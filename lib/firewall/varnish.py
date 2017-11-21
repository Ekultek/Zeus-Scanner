import re

from lib.core.common import HTTP_HEADER


__item__ = "Varnish FireWall (OWASP)"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", None)
    status = kwargs.get("status", None)
    detection_schema = (
        re.compile(r"\bXID: \d+", re.I),
        re.compile(r"varnish\Z", re.I),
        re.compile(r"varnish"), re.I
    )
    for detection in detection_schema:
        if detection.search(content) is not None and status == 404:
            return True
        elif detection.search(headers.get(HTTP_HEADER.VIA)) is not None:
            return True
        elif detection.search(headers.get(HTTP_HEADER.SERVER)) is not None:
            return True
