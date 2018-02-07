import re
import sys
try:
    import urllib2  # python 2
except ImportError:
    import urllib.request as urllib2  # python 3
import json
import platform

import requests
from bs4 import BeautifulSoup

import lib.core.common
import lib.core.settings


def find_url(params, search="https://github.com/ekultek/zeus-scanner/issues"):
    """
    get the URL that your issue is created at
    """
    retval = "https://github.com{}"
    href = None
    searcher = re.compile(params, re.I)
    req = requests.get(search)
    status, html = req.status_code, req.content
    if status == 200:
        split_information = str(html).split("\n")
        for i, line in enumerate(split_information):
            if searcher.search(line) is not None:
                href = split_information[i-1]
    if href is not None:
        soup = BeautifulSoup(href, "html.parser")
        for item in soup.findAll("a"):
            link = item.get("href")
            return retval.format(link)
    return None


def request_issue_creation():
    if not lib.core.settings.get_md5sum():
        lib.core.settings.logger.fatal(lib.core.settings.set_color(
            "it appears that your checksums did not match, therefore it is assumed "
            "that you have edited some of the code, issue request denied", level=50
        ))
        lib.core.common.shutdown()

    question = lib.core.common.prompt(
        "would you like to create an anonymous issue and post it to Zeus's Github", opts="yN"
    )
    if question.lower().startswith("n"):
        lib.core.settings.logger.error(lib.core.settings.set_color(
            "Zeus has experienced an internal error and cannot continue, shutting down", level=40
        ))
        lib.core.common.shutdown()

    lib.core.settings.fix_log_file()
    lib.core.settings.logger.info(lib.core.settings.set_color(
        "Zeus got an unexpected error and will automatically create an issue for this error, please wait"
    ))

    def __extract_stacktrace(file_data):
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "extracting traceback from log file"
        ))
        retval, buff_mode, _buffer = [], False, ""
        with open(file_data, "r+") as log:
            for line in log:
                if "Traceback" in line:
                    buff_mode = True
                if line and len(line) < 5:
                    buff_mode = False
                    retval.append(_buffer)
                    _buffer = ""
                if buff_mode:
                    if len(line) > 400:
                        line = line[:400] + "\n"
                    _buffer += line
        return "".join(retval)

    lib.core.settings.logger.info(lib.core.settings.set_color(
        "getting authorization"
    ))

    token = lib.core.settings.get_token(lib.core.settings.GITHUB_AUTH_PATH)

    current_log_file = lib.core.settings.get_latest_log_file(lib.core.settings.CURRENT_LOG_FILE_PATH)
    stacktrace = __extract_stacktrace(current_log_file)
    identifier = lib.core.settings.create_identifier(stacktrace)
    issue_title = "Unhandled exception ({})".format(identifier)
    ff_version = lib.core.settings.get_browser_version()
    log_file_information = lib.core.settings.tails(current_log_file)

    issue_data = {
        "title": issue_title,
        "body": "Zeus version:\n`{}`\n\n"
                "Firefox version:\n`{}`\n\n"
                "Geckodriver version:\n`{}`\n\n"
                "Error info:\n```{}```\n\n"
                "Running details:\n`{}`\n\n"
                "Commands used:\n`{}`\n\n"
                "Log file info:\n```{}```".format(
                     lib.core.settings.VERSION,
                     "{}".format(ff_version),
                     open(lib.core.settings.GECKO_VERSION_INFO_PATH).read(),
                     str(stacktrace),
                     str(platform.platform()),
                     " ".join(sys.argv),
                     log_file_information
                ),
    }

    _json_data = json.dumps(issue_data)
    if sys.version_info > (3,):  # python 3
        _json_data = _json_data.encode("utf-8")

    try:
        req = urllib2.Request(
            url="https://api.github.com/repos/ekultek/zeus-scanner/issues", data=_json_data,
            headers={"Authorization": "token {}".format(token)}
        )
        urllib2.urlopen(req, timeout=10).read()
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "issue has been created successfully with the following name '{}', your unique identifier "
            "for this issue is '{}' and the URL to your issue is '{}'".format(
                issue_title, identifier, find_url(identifier)
            )
        ))
    except Exception as e:
        lib.core.settings.logger.exception(lib.core.settings.set_color(
            "failed to auto create the issue, got exception '{}', "
            "you may manually create an issue".format(e), level=50
        ))
