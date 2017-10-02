import base64

from lib.settings import (
    logger,
    set_color
)


def tamper(payload, warning=True, **kwargs):
    if warning:
        logger.warning(set_color(
            "base64 tamper scripts may increase the possibility of not finding vulnerabilities "
            "in otherwise vulnerable sites...", level=30
        ))
    return base64.b64encode(payload)