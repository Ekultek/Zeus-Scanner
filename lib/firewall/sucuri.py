import re


__item__ = "Sucuri Firewall (Sucuri Cloudproxy)"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", None)
    detection_schema = (
        re.compile(r"Access Denied - Sucuri Website Firewall"),
        re.compile(r"Sucuri WebSite Firewall - CloudProxy - Access Denied"),
        re.compile(r"Questions\?.+cloudproxy@sucuri\.net")
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
    if headers is not None:
        headers = str(headers)
        if re.compile(r"X-Sucuri-ID", re.I).search(headers) is not None:
            return True
