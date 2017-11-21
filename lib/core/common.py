import os
import re
import json
import time

from lxml import etree

import lib.core.settings


class HTTP_HEADER:
    ACCEPT = "Accept"
    ACCEPT_CHARSET = "Accept-Charset"
    ACCEPT_ENCODING = "Accept-Encoding"
    ACCEPT_LANGUAGE = "Accept-Language"
    AUTHORIZATION = "Authorization"
    CACHE_CONTROL = "Cache-Control"
    CONNECTION = "Connection"
    CONTENT_ENCODING = "Content-Encoding"
    CONTENT_LENGTH = "Content-Length"
    CONTENT_RANGE = "Content-Range"
    CONTENT_TYPE = "Content-Type"
    COOKIE = "Cookie"
    EXPIRES = "Expires"
    HOST = "Host"
    IF_MODIFIED_SINCE = "If-Modified-Since"
    LAST_MODIFIED = "Last-Modified"
    LOCATION = "Location"
    PRAGMA = "Pragma"
    PROXY_AUTHORIZATION = "Proxy-Authorization"
    PROXY_CONNECTION = "Proxy-Connection"
    RANGE = "Range"
    REFERER = "Referer"
    REFRESH = "Refresh"  # Reference: http://stackoverflow.com/a/283794
    SERVER = "Server"
    SET_COOKIE = "Set-Cookie"
    TRANSFER_ENCODING = "Transfer-Encoding"
    URI = "URI"
    USER_AGENT = "User-Agent"
    VIA = "Via"
    X_CACHE = "X-Cache"
    X_POWERED_BY = "X-Powered-By"
    X_DATA_ORIGIN = "X-Data-Origin"
    X_FRAME_OPT = "X-Frame-Options"
    X_FORWARDED_FROM = "X-Forwarded-From"


def write_to_log_file(data_to_write, path, filename, blacklist=False):
    """
    write all found data to a log file
    """
    lib.core.settings.create_dir(path.format(os.getcwd()))
    full_file_path = "{}/{}".format(
        path.format(os.getcwd()), filename.format(len(os.listdir(path.format(
            os.getcwd()
        ))) + 1)
    )
    skip_log_schema = ("url-log", "blackwidow-log", "zeus-log", "extracted", ".blacklist", "gist-match")
    to_search = filename.split("-")[0]
    amount = len([f for f in os.listdir(path) if to_search in f])
    new_filename = "{}({}).{}".format(
                    filename.split("-")[0], amount, filename.split(".")[-1]
                )
    with open(full_file_path, "a+") as log:
        data = re.sub(r'\s+', '', log.read())
        if re.match(r'^<.+>$', data):  # matches HTML and XML
            try:
                log.write(etree.tostring(data_to_write, pretty_print=True))
            except TypeError:
                return write_to_log_file(data_to_write, path, new_filename)
        elif amount > 0 and not any(_ in filename for _ in list(skip_log_schema)):
            return write_to_log_file(data_to_write, path, new_filename)
        elif blacklist:
            items = log.readlines()
            if any(d.strip() == data_to_write for d in items):
                lib.core.settings.logger.info(lib.core.settings.set_color(
                    "query already in blacklist..."
                ))
                return full_file_path
            else:
                log.write(data_to_write + "\n")
        else:
            if isinstance(data_to_write, list):
                for item in data_to_write:
                    item = item.strip()
                    log.write(str(item) + "\n")
            elif isinstance(data_to_write, (tuple, set)):
                for item in list(data_to_write):
                    item = item.strip()
                    log.write(str(item) + "\n")
            elif isinstance(data_to_write, dict):
                json.dump(data_to_write, log, sort_keys=True, indent=4)
            else:
                log.write(data_to_write + "\n")
    lib.core.settings.logger.info(lib.core.settings.set_color(
        "successfully wrote found items to '{}'...".format(full_file_path)
    ))
    return full_file_path


def start_up():
    """
    start the program and display the time it was started
    """
    print(
        "\n\n[*] starting up at {}..\n\n".format(time.strftime("%H:%M:%S"))
    )


def shutdown():
    """
    shut down the program and the time it stopped
    """
    print(
        "\n\n[*] shutting down at {}..\n\n".format(time.strftime("%H:%M:%S"))
    )
    exit(0)


def prompt(question, opts=None, default=None):
    """
    ask a question
    """
    if opts is not None and default is None:
        options = '/'.join(opts)
        return raw_input(
            "[{} {}] {}[{}]: ".format(
                time.strftime("%H:%M:%S"),
                "PROMPT", question, options
            )
        )
    elif default is not None:
        if opts is not None:
            options = "/".join(opts)
            print(
                "[{} {}] {}[{}] {}".format(
                    time.strftime("%H:%M:%S"), "PROMPT",
                    question, options, default
                )
            )
            return default
        else:
            print(
                "[{} {}] {} {}".format(
                    time.strftime("%H:%M:%S"), "PROMPT",
                    question, default
                )
            )
            return default
    else:
        return raw_input(
            "[{} {}] {} ".format(
                time.strftime("%H:%M:%S"), "PROMPT", question
            )
        )