import random


def tamper(payload, **kwargs):
    retval = ""
    nums = [0, 1]

    for char in payload:
        random_int = random.choice(nums)
        if random_int == 1:
            retval += char.upper()
        else:
            retval += char
    return retval
