def tamper(payload, **kwargs):
    retval = hex(hash(payload))
    if "-" in str(retval):
        return retval[1:-1]
    else:
        return retval
