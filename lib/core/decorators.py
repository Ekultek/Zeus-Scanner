import signal
from functools import wraps

import lib.core.errors
import lib.core.settings


class TimeOut:

    def __init__(self, seconds=1, error_message='Timeout'):
        self.seconds = seconds
        self.error_message = error_message

    def handle_timeout(self, signum, frame):
        raise lib.core.errors.PortScanTimeOutException(self.error_message)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, type_, value, traceback):
        signal.alarm(0)


def cache(func):
    """
    if we come across the same URL more then once, it will be cached into memory
    so that we don't have to test it again
    """
    __cache = {}

    @wraps(func)
    def func_wrapper(*args, **kwargs):
        if args in __cache:
            return __cache[args]
        else:
            __to_cache = func(*args, **kwargs)
            __cache[args] = __to_cache
            return __to_cache

    return func_wrapper
