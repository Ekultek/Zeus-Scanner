from lib.core.settings import (
    logger,
    set_color
)


def tamper(payload, **kwargs):
    warning = kwargs.get("warning", True)
    if warning:
        logger.warning(set_color(
            "NULL encoding tamper scripts may increase the possibility of not finding vulnerabilities "
            "in otherwise vulnerable sites", level=30
        ))

    retval = ""
    encoder = "%00"
    for char in payload:
        if char == " ":
            char = encoder
            retval += char
        else:
            retval += char
    return retval