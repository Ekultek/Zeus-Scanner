import string

from lib.core.settings import (
    logger,
    set_color
)


def tamper(payload, **kwargs):
    warning = kwargs.get("warning", True)

    if warning:
        logger.warning(set_color(
            "enclosing brackets is meant to be used as an obfuscation "
            "against an already valid vulnerable site", level=30
        ))

    to_enclose = string.digits
    retval = ""
    for char in payload:
        if char in to_enclose:
            char = "['{}']".format(char)
            retval += char
        else:
            retval += char
    return retval