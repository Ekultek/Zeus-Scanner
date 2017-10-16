import os
import sys
try:
    import urllib2  # python 2
except ImportError:
    import urllib.request as urllib2  # python 3
import json
import platform

from base64 import b64decode

import lib.core.settings


def __get_encoded_string(filename="{}/var/auto_issue/oauth"):
    with open(filename.format(os.getcwd())) as data:
        return data.read()


def get_decode_num(data):
    return data.split(":")[-1]


def decode(n, token):
    token = token.split(":")[0]
    for _ in range(int(n)):
        token = b64decode(token)
    return token


def request_issue_creation():
    question = lib.core.settings.prompt(
        "would you like to create an anonymous issue and post it to Zeus's Github", opts="yN"
    )
    if question.lower().startswith("n"):
        lib.core.settings.logger.error(lib.core.settings.set_color(
            "Zeus has experienced an internal error and cannot continue, shutting down...", level=40
        ))
        lib.core.settings.shutdown()

    lib.core.settings.fix_log_file()
    lib.core.settings.logger.info(lib.core.settings.set_color(
        "Zeus got an unexpected error and will automatically create an issue for this error, please wait..."
    ))

    def __extract_stacktrace(file_data):
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "extracting traceback from log file..."
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
                        line = line[:400] + "...\n"
                    _buffer += line
        return "".join(retval)

    lib.core.settings.logger.info(lib.core.settings.set_color(
        "getting authorization..."
    ))

    encoded = __get_encoded_string()
    n = get_decode_num(encoded)
    token = decode(n, encoded)

    current_log_file = lib.core.settings.get_latest_log_file(lib.core.settings.CURRENT_LOG_FILE_PATH)
    stacktrace = __extract_stacktrace(current_log_file)
    issue_title = stacktrace.split("\n")[-2]
    ff_version = lib.core.settings.get_browser_version()

    issue_data = {
        "title": issue_title,
        "body": "Zeus version:\n`{}`\n\n"
                "Firefox version:\n`{}`\n\n"
                "Geckodriver version:\n`{}`\n\n"
                "Error info:\n```{}````\n\n"
                "Running details:\n`{}`\n\n"
                "Commands used:\n`{}`\n\n"
                "Log file info:\n```{}```".format(
                     lib.core.settings.VERSION,
                     "{}".format(ff_version),
                     open(lib.core.settings.GECKO_VERSION_INFO_PATH).read(),
                     str(stacktrace),
                     str(platform.platform()),
                     " ".join(sys.argv),
                     open(current_log_file).read()
                ),
    }

    _json_data = json.dumps(issue_data)
    if sys.version_info > (3,):
        _json_data = _json_data.encode("utf-8")

    try:
        req = urllib2.Request(
            url="https://api.github.com/repos/ekultek/zeus-scanner/issues", data=_json_data,
            headers={"Authorization": "token {}".format(token)}
        )
        urllib2.urlopen(req, timeout=10).read()
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "issue has been created successfully with the following name '{}'...".format(issue_title)
        ))
    except Exception as e:
        lib.core.settings.logger.exception(lib.core.settings.set_color(
            "failed to auto create the issue, got exception '{}', "
            "you may manually create an issue...".format(e), level=50
        ))
