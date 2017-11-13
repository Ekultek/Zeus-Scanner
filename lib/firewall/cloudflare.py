import re


__item__ = "CloudFlare Web Application Firewall (CloudFlare)"


def detect(content, **kwargs):
    headers = kwargs.get("headers", None)
    content = str(content)
    detection_schemas = (re.compile(r"CloudFlare Ray ID:|var CloudFlare=", re.I),)
    for detection in detection_schemas:
        if detection.search(content) is not None:
            return True
    try:
        if re.compile(r"cloudflare-nginx", re.I).search(headers.get("Server")) is not None:
            return True
        if re.compile(r"\A__cfduid=", re.I).search(headers.get("Cookie")) is not None:
            return True
    except Exception:
        pass
