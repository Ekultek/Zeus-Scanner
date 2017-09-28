import base64


def tamper(payload, **kwargs):
    return base64.b64encode(payload)