import os
import re
import importlib

import requests
from xml.dom import minidom
from requests.exceptions import ConnectionError

from var.auto_issue.github import request_issue_creation
from lib.core.common import (
    write_to_log_file,
    HTTP_HEADER
)
from lib.core.settings import (
    logger, set_color,
    HEADER_XML_DATA,
    proxy_string_to_dict,
    create_random_ip,
    replace_http,
    HEADER_RESULT_PATH,
    COOKIE_LOG_PATH,
    PROTECTION_CHECK_PAYLOAD,
    DETECT_FIREWALL_PATH,
    ISSUE_LINK,
    DBMS_ERRORS,
    UNKNOWN_FIREWALL_FINGERPRINT_PATH,
    UNKNOWN_FIREWALL_FILENAME,
    COOKIE_FILENAME,
    HEADERS_FILENAME
)


def detect_protection(url, **kwargs):
    verbose = kwargs.get("verbose", False)
    agent = kwargs.get("agent", None)
    proxy = kwargs.get("proxy", None)
    xforward = kwargs.get("xforward", False)

    if xforward:
        ip_list = (
            create_random_ip(),
            create_random_ip(),
            create_random_ip()
        )
        headers = {
            HTTP_HEADER.CONNECTION: "close",
            HTTP_HEADER.USER_AGENT: agent,
            HTTP_HEADER.X_FORWARDED_FROM: "{}, {}, {}".format(ip_list[0], ip_list[1], ip_list[2])
        }
    else:
        headers = {
            HTTP_HEADER.CONNECTION: "close",
            HTTP_HEADER.USER_AGENT: agent
        }

    url = "{} {}".format(url.strip(), PROTECTION_CHECK_PAYLOAD)

    if verbose:
        logger.debug(set_color(
            "attempting connection to '{}'...".format(url), level=10
        ))
    try:
        protection_check_req = requests.get(
            url, params=headers, proxies=proxy_string_to_dict(proxy), timeout=20
        )

        html, status, headers = protection_check_req.content, protection_check_req.status_code, protection_check_req.headers

        for dbms in DBMS_ERRORS:  # make sure there are no DBMS errors in the HTML
            for regex in DBMS_ERRORS[dbms]:
                if re.compile(regex).search(html) is not None:
                    logger.info(set_color(
                        "it appears that the WAF/IDS/IPS check threw a DBMS error and may be vulnerable "
                        "to SQL injection attacks. it appears the backend DBMS is '{}'...".format(dbms), level=25
                    ))
                    return None

        retval = []
        if status != 200 and "not found" not in html.lower():
            file_list = [f for f in os.listdir(DETECT_FIREWALL_PATH) if not any(ex in f for ex in ["__init__", ".pyc"])]
            for item in file_list:
                item = item[:-3]
                detection_name = "lib.firewall.{}"
                detection_name = detection_name.format(item)
                detection_name = importlib.import_module(detection_name)
                if detection_name.detect(html, headers=headers, status=status):
                    retval.append(detection_name.__item__)
            if len(retval) > 1:
                if "Generic (Unknown)" in retval:
                    item = retval.index("Generic (Unknown)")
                    del retval[item]
            else:
                if retval[0] == "Generic (Unknown)":
                    logger.warning(set_color(
                        "identified WAF/IDS/IPS is unknown to Zeus, if you know the firewall and the context "
                        "of the firewall, please create an issue ({}), fingerprint of the firewall will be "
                        "written to a log file...".format(ISSUE_LINK), level=30
                    ))
                    full_finger_print = "HTTP/1.1 {}\n{}\n{}".format(status, headers, html)
                    write_to_log_file(
                        full_finger_print, UNKNOWN_FIREWALL_FINGERPRINT_PATH, UNKNOWN_FIREWALL_FILENAME.format(
                            replace_http(url)
                        )
                    )
        else:
            retval = None

        return ''.join(retval) if isinstance(retval, list) else retval

    except Exception as e:
        if "Read timed out." or "Connection reset by peer" in str(e):
            logger.warning(set_color(
                "detection request timed out, assuming no protection and continuing...", level=30
            ))
            return None
        else:
            logger.exception(set_color(
                "Zeus ran into an unexpected error '{}'...".format(e), level=50
            ))
            request_issue_creation()
            return None


def load_xml_data(path, start_node="header", search_node="name"):
    """
    load the XML data
    """
    retval = []
    fetched_xml = minidom.parse(path)
    item_list = fetched_xml.getElementsByTagName(start_node)
    for value in item_list:
        retval.append(value.attributes[search_node].value)
    return retval


def load_headers(url, **kwargs):
    """
    load the URL headers
    """
    agent = kwargs.get("agent", None)
    proxy = kwargs.get("proxy", None)
    xforward = kwargs.get("xforward", False)

    if proxy is not None:
        proxy = proxy_string_to_dict(proxy)
    if not xforward:
        header_value = {
            HTTP_HEADER.CONNECTION: "close",
            HTTP_HEADER.USER_AGENT: agent
        }
    else:
        ip_list = create_random_ip(), create_random_ip(), create_random_ip()
        header_value = {
            HTTP_HEADER.CONNECTION: "close",
            HTTP_HEADER.USER_AGENT: agent,
            HTTP_HEADER.X_FORWARDED_FROM: "{}, {}, {}".format(
                ip_list[0], ip_list[1], ip_list[2]
            )
        }
    req = requests.get(url, params=header_value, proxies=proxy, timeout=10)
    if len(req.cookies) > 0:
        logger.info(set_color(
            "found a request cookie, saving to file...", level=25
        ))
        try:
            cookie_start = req.cookies.keys()
            cookie_value = req.cookies.values()
            write_to_log_file(
                "{}={}".format(''.join(cookie_start), ''.join(cookie_value)),
                COOKIE_LOG_PATH, COOKIE_FILENAME.format(replace_http(url))
            )
        except Exception:
            write_to_log_file(
                [c for c in req.cookies.itervalues()], COOKIE_LOG_PATH,
                COOKIE_FILENAME.format(replace_http(url))
            )
    return req.headers


def compare_headers(found_headers, comparable_headers):
    """
    compare the headers against one another
    """
    retval = set()
    for header in comparable_headers:
        if header in found_headers:
            retval.add(header)
    return retval


def main_header_check(url, **kwargs):
    """
    main function
    """
    verbose = kwargs.get("verbose", False)
    agent = kwargs.get("agent", None)
    proxy = kwargs.get("proxy", None)
    xforward = kwargs.get("xforward", False)
    identify = kwargs.get("identify", True)

    protection = {"hostname": url}
    definition = {
        "x-xss": ("protection against XSS attacks", "XSS"),
        "strict-transport": ("protection against unencrypted connections (force HTTPS connection)", "HTTPS"),
        "x-frame": ("protection against clickjacking vulnerabilities", "CLICKJACKING"),
        "x-content": ("protection against MIME type attacks", "MIME"),
        "public-key": ("protection to reduce success rates of MITM attacks", "MITM"),
        "content-security": ("protection against multiple attacks", "ALL")
    }

    if identify:
        logger.info(set_color(
            "checking if target URL is protected by some kind of WAF/IPS/IDS..."
        ))
        identified = detect_protection(url, proxy=proxy, agent=agent, verbose=verbose, xforward=xforward)
        if identified is None:
            logger.info(set_color(
                "no WAF/IDS/IPS has been identified on target URL...", level=25
            ))
        else:
            logger.warning(set_color(
                "the target URL WAF/IDS/IPS has been identified as '{}'...".format(identified), level=30
            ))

    if verbose:
        logger.debug(set_color(
            "loading XML data...", level=10
        ))
    comparable_headers = load_xml_data(HEADER_XML_DATA)
    logger.info(set_color(
        "attempting to get request headers for '{}'...".format(url.strip())
    ))
    try:
        found_headers = load_headers(url, proxy=proxy, agent=agent, xforward=xforward)
    except (ConnectionError, Exception) as e:
        if "Read timed out." or "Connection reset by peer" in str(e):
            found_headers = None
        else:
            logger.exception(set_color(
                "Zeus has hit an unexpected error and cannot continue '{}'...".format(e), level=50
            ))
            request_issue_creation()

    if found_headers is not None:
        if verbose:
            logger.debug(set_color(
                "fetched {}...".format(found_headers), level=10
            ))
        headers_established = [str(h) for h in compare_headers(found_headers, comparable_headers)]
        for key in definition.iterkeys():
            if any(key in h.lower() for h in headers_established):
                logger.warning(set_color(
                    "provided target has {}...".format(definition[key][0]), level=30
                ))
        for key in found_headers.iterkeys():
            protection[key] = found_headers[key]
        logger.info(set_color(
            "writing found headers to log file...", level=25
        ))
        return write_to_log_file(protection, HEADER_RESULT_PATH, HEADERS_FILENAME.format(replace_http(url)))
    else:
        logger.error(set_color(
            "unable to retrieve headers for site '{}'...".format(url.strip()), level=40
        ))
