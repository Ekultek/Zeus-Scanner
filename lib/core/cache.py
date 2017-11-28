from functools import wraps

import lib.core.settings


def cache(func):
    """
    if we come across the same URL more then once, it will be cached into memory
    so that we don't have to test it again
    """
    __cache = {}

    @wraps(func)
    def func_wrapper(*args, **kwargs):
        if args in __cache:
            lib.core.settings.logger.warning(lib.core.settings.set_color(
                "cached detection has shown that the target URL WAF/IPS/IDS is '{}'...".format(
                    __cache[args]
                ), level=35
            ))
            return __cache[args]
        else:
            __to_cache = func(*args, **kwargs)
            __cache[args] = __to_cache
            return __to_cache

    return func_wrapper
