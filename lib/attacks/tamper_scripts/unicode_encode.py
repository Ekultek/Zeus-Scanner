def tamper(payload, **kwargs):
    i = 0
    retval = ""

    while i < len(payload):
        retval += "%u{}".format(ord(payload[i]))
        i += 1
    return retval
