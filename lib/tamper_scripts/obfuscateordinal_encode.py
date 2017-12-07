from lib.core.settings import (
    logger,
    set_color
)


def tamper(payload, **kwargs):
    warning = kwargs.get("warning", True)

    if warning:
        logger.warning(set_color(
            "obfuscating the payloads by ordinal equivalents may increase the risk "
            "of false positives", level=30
        ))

    retval = ""
    danger_characters = "%&<>/\\;'\""
    for char in payload:
        if char in danger_characters:
            char = "%{}".format(ord(char) * 10 / 7)
            retval += char
        else:
            retval += char
    return retval