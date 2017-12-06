import random


def tamper(payload, **kwargs):
    possible_spaces = [2, 3, 4]
    retval = ""
    encoder = "/**/"
    for char in retval:
        if char == " ":
            retval += encoder * random.choice(possible_spaces)
        else:
            retval += char
    return retval