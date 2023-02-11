import os
import re
import json
import time
import shlex
import subprocess
from urllib.parse import (unquote)
import requests
from lxml import etree

import lib.core.settings

# reference https://en.wikipedia.org/wiki/List_of_HTTP_status_codes
STATUS_CODES = {
    100: "continue", 101: "switching protocols", 102: "processing",
    200: "OK", 201: "created", 202: "accepted", 203: "non-authoritative information",
    204: "no content", 205: "reset content", 206: "partial content",
    207: "multi-status", 208: "already reported", 226: "IM used",
    300: "multiple choices", 301: "moved permanently",  302: "found redirect",
    303: "see other", 304: "not modified", 305: "use proxy",
    306: "switch proxy", 308: "permanent redirect",
    400: "bad request", 401: "unauthorized", 402: "payment required",
    403: "forbidden", 404: "not found", 405: "method not allowed",
    406: "not acceptable", 407: "proxy authentication required", 408: "request timed out",
    409: "conflict", 410: "gone", 411: "length required", 412: "precondition failed",
    413: "payload to large", 414: "URI too long", 415: "unsupported media type",
    416: "range not satisfiable", 417: "expectation failed", 418: "im a teapot {EASTER EGG!}",
    421: "misdirected request", 422: "unprocesseable entity", 423: "locked",
    424: "failed dependency", 426: "upgrade requried", 428: "precondition required",
    429: "to many requests", 431: "request headers field too large",
    451: "unavailable for legal reasons",
    500: "internal server error", 501: "not implemented", 502: "bad gateway",
    503: "service unavailable", 504: "gateway timeout", 505: "HTTP version not supported",
    506: "variant also negotiable", 507: "insufficient storage", 508: "loop detected",
    510: "not extended", 511: "network authentication required", "other": "unexpected error code"
}


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
    X_FORWARDED_FOR = "X-Forwarded-For"


class URLParser(object):

    def __init__(self, url):
        self.url = url
        self.url_match_regex = re.compile(r"((https?):((//)|(\\\\))+([\w\d:#@%/;$()~_?\+-=\\\.&](#!)?)*)")
        self.webcache_regex = re.compile(r"cache:(.{,16})?:")
        self.possible_leftovers = ("<", ">", ";", ",")
        self.webcache_schema = "webcache"
        self.constant_ip_ban_splitter = "continue="
        self.content_ip_ban_seperator = ("Fid", "&gs_")

    def extract_webcache_url(self, splitter="+"):
        """
        Extract the URL from Google's webcache URL
        """
        url = self.url
        data = self.webcache_regex.split(url)
        to_extract = data[2].split(splitter)
        extracted = to_extract[0]
        if self.url_match_regex.match(extracted):
            return extracted
        return None

    def extract_ip_ban_url(self):
        """
        Extract the true URL from Google's IP ban URL
        """
        url = unquote(self.url)
        to_use_separator = None
        retval_url = None
        url_data_list = url.split(self.constant_ip_ban_splitter)
        for item in url_data_list:
            for sep in list(self.content_ip_ban_seperator):
                if sep in item:
                    to_use_separator = sep
            retval_url = item.split(to_use_separator)
        return unquote(retval_url[0])

    def strip_url_leftovers(self):
        """
        strip any leftovers that come up with the URL every now and then
        """
        url = self.url
        for possible in self.possible_leftovers:
            if possible in url:
                url = url.split(possible)[0]
        return url


def write_to_log_file(data_to_write, path, filename, blacklist=False):
    """
    Write all found data to a log file
    """
    lib.core.settings.create_dir(path.format(os.getcwd()))
    full_file_path = "{}/{}".format(
        path.format(os.getcwd()), filename.format(len(os.listdir(path.format(
            os.getcwd()
        ))) + 1)
    )
    skip_log_schema = (
        "url-log", "blackwidow-log", "zeus-log",
        "extracted", ".blacklist", "sqli-sites"
    )
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
                    "query already in blacklist"
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
        "Successfully wrote found items to '{}'".format(full_file_path)
    ))
    return full_file_path


def start_up():
    """
    Start the program and display the time it was started
    """
    print(
        "\n\n[*] starting up at {}..\n\n".format(time.strftime("%H:%M:%S"))
    )


def shutdown():
    """
    Shut down the program and the time it stopped
    """
    print(
        "\n\n[*] shutting down at {}.\n\n".format(time.strftime("%H:%M:%S"))
    )
    exit(0)


def prompt(question, opts=None, default=None, paused=False):
    """
    Ask a question
    """
    if opts is not None and default is None:
        options = '/'.join(opts)
        return input(
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
    elif opts is None and default is None and paused:
        opts = "[(s)kip (e)xit]"
        question_ = input(
            "[{} {}] {} {}: ".format(
                time.strftime("%H:%M:%S"), "PROMPT", question, opts
            )
        )
        if question_.lower().startswith("s"):
            return True
        return False
    else:
        return input(
            "[{} {}] {} ".format(
                time.strftime("%H:%M:%S"), "PROMPT", question
            )
        )


def pause():
    """
    Interactive pause function, as of now you are only able to skip and exit
    from this function
    """
    message = "Program has been paused, how do you want to proceed?"
    return prompt(
        message, paused=True
    )


def run_fix(message, command, fail_message, exit_process=False):
    """
    Run the fix script for the program
    """
    do_fix = prompt(
        message, opts="yN"
    )
    if do_fix.lower().startswith("y"):
        cmd = shlex.split(command)
        subprocess.call(cmd)
        if exit_process:
            lib.core.settings.logger.info(lib.core.settings.set_color(
                "Command completed successfully, should be safe to re-run Zeus"
            ))
    else:
        lib.core.settings.logger.fatal(lib.core.settings.set_color(
            fail_message, level=50
        ))


def get_page(url, **kwargs):
    agent = kwargs.get("agent", None)
    proxy = kwargs.get("proxy", None)
    xforward = kwargs.get("xforward", False)
    auth = kwargs.get("auth", None)
    skip_verf = kwargs.get("skip_verf", False)

    if agent is None:
        agent = lib.core.settings.DEFAULT_USER_AGENT

    if xforward:
        ip_list = (
            lib.core.settings.create_random_ip(),
            lib.core.settings.create_random_ip(),
            lib.core.settings.create_random_ip()
        )
        headers = {
            HTTP_HEADER.CONNECTION: "close",
            HTTP_HEADER.USER_AGENT: agent,
            HTTP_HEADER.X_FORWARDED_FOR: "{}, {}, {}".format(
                ip_list[0], ip_list[1], ip_list[2]
            )
        }
    elif auth:
        headers = {
            HTTP_HEADER.CONNECTION: "close",
            HTTP_HEADER.USER_AGENT: agent,
            HTTP_HEADER.AUTHORIZATION: "{}".format(
                auth
            )
        }
    else:
        headers = {
            HTTP_HEADER.CONNECTION: "close",
            HTTP_HEADER.USER_AGENT: agent
        }

    if proxy is not None:
        proxies = {
            "https": proxy,
            "http": proxy
        }
    else:
        proxies = {}

    if proxy is not None and "127.0.0.1" in proxy:
        req = requests.get(url, params=headers, proxies=proxies, verify=False, timeout=40)
    else:
        req = requests.get(url, params=headers, proxies=proxies, verify=False, timeout=20)

    status = req.status_code
    html = req.content
    headers = req.headers
    return req, status, html, headers
