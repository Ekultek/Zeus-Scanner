import re

from lib.core.settings import PROTECTION_CHECK_PAYLOAD


__item__ = "Generic (Unknown)"


def detect(content, **kwargs):
    content = str(content)
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
