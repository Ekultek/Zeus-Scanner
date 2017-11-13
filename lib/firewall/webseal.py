import re


__item__ = "IBM Security Access Manager WebSEAL"


def detect(content, **kwargs):
    content = str(content)
    detection_schema = (
        re.compile(r"\bWebSEAL\b"), re.compile(r"\bIBM\b")
    )
    for detection in list(detection_schema):
        if detection.search(content) is not None:
            return True
