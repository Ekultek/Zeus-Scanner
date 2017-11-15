import re

from lib.core.settings import PROTECTION_CHECK_PAYLOAD


__item__ = "Generic (Unknown)"


def detect(content, **kwargs):
    content = str(content)
    status = kwargs.get("status", None)
    if status == 403:
        # if the error HTML is an Apache error, Apache has a tendency to be fucking stupid
        # and output 403 errors when you are trying to do something fun. mostly because
        # Apache is a killer of fun and doesn't like anything decent in this life.
        if re.compile(r"<.+>403 Forbidden<.+.>", re.I).search(content) is not None:
            return False
    detection_schema = (
        re.compile("blocked", re.I), re.compile("forbidden", re.I),
        re.compile("illegal", re.I), re.compile("reported", re.I),
        re.compile("logged", re.I), re.compile("access denied", re.I),
        re.compile("ip address logged", re.I)
    )
    for detection in detection_schema:
        if detection.search(content) is not None:
            return True
    if PROTECTION_CHECK_PAYLOAD in content:
        return True
