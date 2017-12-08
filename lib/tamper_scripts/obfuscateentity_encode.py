from lib.core.settings import (
    logger,
    set_color
)


def tamper(payload, **kwargs):
    warning = kwargs.get("warning", True)

    if warning:
        logger.warning(set_color(
            "obfuscating payloads by their entity encoding equivalent may increase the "
            "risk of false positives", level=30
        ))

    skip = ";"
    encoding_schema = {
        " ": "&nbsp;", "<": "&lt;", ">": "&gt;",
        "&": "&amp;", '"': "&quot;", "'": "&apos;",
    }
    retval = ""
    for char in str(payload):
        if char in encoding_schema.iterkeys():
            retval += encoding_schema[char]
        elif char not in encoding_schema.iterkeys() and char != skip:
            retval += char
        else:
            retval += char
    return retval
