import re


__item__ = "Squid Proxy (IDS)"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"squid", re.I),
        re.compile(r"Access control configuration prevents", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
    if headers is not None:
        headers = str(headers)
        detection_schema = (
            re.compile(r"X.Squid.Error", re.I),
            re.compile(r"squid", re.I)
        )
        for detection in detection_schema:
            if detection.search(headers) is not None:
                return True
