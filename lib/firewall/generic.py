import re

from lib.core.common import  HTTP_HEADER
from lib.core.settings import PROTECTION_CHECK_PAYLOAD


__item__ = "Generic (Unknown)"


def detect(content, **kwargs):
    content = str(content)
    headers = kwargs.get("headers", None)
    status = kwargs.get("status", None)
    if status == 403:
        # if the error HTML is an Apache error, Apache has a tendency to be fucking stupid
        # and output 403 errors when you are trying to do something fun. mostly because
        # Apache is a killer of fun and doesn't like anything decent in this life.
        if re.compile(r"<.+>403 Forbidden<.+.>", re.I).search(content) is not None:
            return False
        if re.compile(r"apache.\d+", re.I).search(headers.get(HTTP_HEADER.SERVER, "")) is not None:
            return False
    # make sure that it's not just a `didn't find what you're looking for` page
    # this will probably help out a lot with random WAF detection
    if status == 200 or "not found" in content.lower():
        return False
    detection_schema = (
        re.compile("blocked", re.I), re.compile("forbidden", re.I),
        re.compile("illegal", re.I), re.compile("reported", re.I),
        re.compile("ip.logged", re.I), re.compile("access.denied", re.I),
        re.compile("ip.address.logged", re.I), re.compile(r"not.acceptable")
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
    if PROTECTION_CHECK_PAYLOAD in content:
        return True
