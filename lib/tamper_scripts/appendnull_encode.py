def tamper(payload, **kwargs):
    return "{}%00".format(payload.strip())