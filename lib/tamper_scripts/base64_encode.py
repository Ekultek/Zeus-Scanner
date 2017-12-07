import base64

from lib.core.settings import (
    logger,
    set_color
)


def tamper(payload, **kwargs):
    warning = kwargs.get("warning", True)
    if warning:
        logger.warning(set_color(
            "base64 tamper scripts may increase the possibility of not finding vulnerabilities "
            "in otherwise vulnerable sites", level=30
        ))
    return base64.b64encode(payload)