def tamper(payload, **kwargs):
    retval = ""
    encoder = "%00"
    for char in payload:
        if char == " ":
            char = encoder
            retval += char
        else:
            retval += char
    return retval