import os
import re
import importlib
import unicodedata

from xml.dom import minidom
from requests.exceptions import ConnectionError

from var.auto_issue.github import request_issue_creation
from lib.core.decorators import cache
from lib.core.common import (
    write_to_log_file,
    shutdown,
    pause,
    get_page,
    HTTP_HEADER
)
from lib.core.settings import (
    logger, set_color,
    HEADER_XML_DATA,
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
    HEADERS_FILENAME,
    SQLI_FOUND_FILENAME,
    SQLI_SITES_FILEPATH,
    DETECT_PLUGINS_PATH
)


def get_charset(html, headers, **kwargs):
    """
    detect the target URL charset
    """
    charset_regex = re.compile(r'charset=[\"]?([a-zA-Z0-9_-]+)', re.I)
    charset = charset_regex.search(html)
    if charset is not None:
        return charset.group(1)
    else:
        content = headers.get(HTTP_HEADER.CONTENT_TYPE, "")
        charset = charset_regex.search(content)
        if charset is not None:
            return charset
    return None


def detect_protection(url, status, html, headers, **kwargs):
    verbose = kwargs.get("verbose", False)

    if verbose:
        logger.debug(set_color(
            "attempting connection to '{}'...".format(url), level=10
        ))
    try:
        # make sure there are no DBMS errors in the HTML
        for dbms in DBMS_ERRORS:
            for regex in DBMS_ERRORS[dbms]:
                if re.compile(regex).search(html) is not None:
                    logger.warning(set_color(
                        "it appears that the WAF/IDS/IPS check threw a DBMS error and may be vulnerable "
                        "to SQL injection attacks. it appears the backend DBMS is '{}', site will be "
                        "saved for further processing...".format(dbms), level=30
                    ))
                    write_to_log_file(url, SQLI_SITES_FILEPATH, SQLI_FOUND_FILENAME)
                    return None

        retval = []
        file_list = [f for f in os.listdir(DETECT_FIREWALL_PATH) if not any(ex in f for ex in ["__init__", ".pyc"])]
        for item in file_list:
            item = item[:-3]
            if verbose:
                logger.debug(set_color(
                    "loading script '{}'...".format(item), level=10
                ))
            detection_name = "lib.firewall.{}"
            detection_name = detection_name.format(item)
            detection_name = importlib.import_module(detection_name)
            if detection_name.detect(html, headers=headers, status=status) is True:
                retval.append(detection_name.__item__)
        if len(retval) != 0:
            if len(retval) >= 2:
                try:
                    del retval[retval.index("Generic (Unknown)")]
                except (Exception, IndexError):
                    logger.warning(set_color(
                        "multiple firewalls identified ({}), displaying most likely...".format(
                            ", ".join([item.split("(")[0] for item in retval])
                        ), level=30
                    ))
                    del retval[retval.index(retval[1])]
                    if len(retval) >= 2:
                        del retval[retval.index(retval[1])]
            if retval[0] == "Generic (Unknown)":
                logger.warning(set_color(
                    "discovered firewall is unknown to Zeus, saving fingerprint to file. "
                    "if you know the details or the context of the firewall please create "
                    "an issue ({}) with the fingerprint, or a pull request with the script...".format(
                        ISSUE_LINK
                    ), level=30
                ))
                fingerprint = "<!---\nHTTP 1.1\nStatus Code: {}\nHTTP Headers: {}\n--->\n{}".format(
                    status, headers, html
                )
                write_to_log_file(fingerprint, UNKNOWN_FIREWALL_FINGERPRINT_PATH, UNKNOWN_FIREWALL_FILENAME)
            return "".join(retval) if isinstance(retval, list) else retval
        else:
            return None

    except Exception as e:
        if "Read timed out." or "Connection reset by peer" in str(e):
            logger.warning(set_color(
                "detection request failed, assuming no protection and continuing...", level=30
            ))
            return None
        else:
            logger.exception(set_color(
                "Zeus ran into an unexpected error '{}'...".format(e), level=50
            ))
            request_issue_creation()
            return None


def detect_plugins(html, headers, **kwargs):
    verbose = kwargs.get("verbose", False)

    try:
        retval = []
        plugin_skip_schema = ("__init__", ".pyc")
        plugin_file_list = [f for f in os.listdir(DETECT_PLUGINS_PATH) if not any(s in f for s in plugin_skip_schema)]
        for plugin in plugin_file_list:
            plugin = plugin[:-3]
            if verbose:
                logger.debug(set_color(
                    "loading script '{}'...".format(plugin), level=10
                ))
            plugin_detection = "lib.plugins.{}"
            plugin_detection = plugin_detection.format(plugin)
            plugin_detection = importlib.import_module(plugin_detection)
            if plugin_detection.search(html, headers=headers) is True:
                retval.append((plugin_detection.__product__, plugin_detection.__description__))
        if len(retval) > 0:
            return retval
        return None
    except Exception as e:
        logger.exception(str(e))
        if "Read timed out." or "Connection reset by peer" in str(e):
            logger.warning(set_color(
                "plugin request failed, assuming no plugins and continuing...", level=30
            ))
            return None
        else:
            logger.exception(set_color(
                "plugin detection has failed with error {}...".format(str(e))
            ))
            request_issue_creation()


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


def load_headers(url, req, **kwargs):
    """
    load the HTTP headers
    """
    literal_match = re.compile(r"\\(\X(\d+)?\w+)?", re.I)

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
    retval = {}
    do_not_use = []
    http_headers = req.headers
    for header in http_headers:
        try:
            # check for Unicode in the string, this is just a safety net in case something is missed
            # chances are nothing will be matched
            if literal_match.search(header) is not None:
                retval[header] = unicodedata.normalize(
                    "NFKD", u"{}".format(http_headers[header])
                ).encode("ascii", errors="ignore")
            else:
                # test to see if there are any unicode errors in the string
                retval[header] = unicodedata.normalize(
                    "NFKD", u"{}".format(http_headers[header])
                ).encode("ascii", errors="ignore")
        # just to be safe, we're going to put all the possible Unicode errors into a tuple
        except (UnicodeEncodeError, UnicodeDecodeError, UnicodeError, UnicodeTranslateError, UnicodeWarning):
            # if there are any errors, we're going to append them to a `do_not_use` list
            do_not_use.append(header)
    # clear the dict so we can re-add to it
    retval.clear()
    for head in http_headers:
        # if the header is in the list, we skip it
        if head not in do_not_use:
            retval[head] = http_headers[head]
    # return a dict of safe unicodeless HTTP headers
    return retval


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
    identify_waf = kwargs.get("identify_waf", True)
    identify_plugins = kwargs.get("identify_plugins", True)
    show_description = kwargs.get("show_description", False)

    protection = {"hostname": url}
    definition = {
        "x-xss": ("protection against XSS attacks", "XSS"),
        "strict-transport": ("protection against unencrypted connections (force HTTPS connection)", "HTTPS"),
        "x-frame": ("protection against clickjacking vulnerabilities", "CLICKJACKING"),
        "x-content": ("protection against MIME type attacks", "MIME"),
        "x-csrf": ("protection against Cross-Site Forgery attacks", "CSRF"),
        "x-xsrf": ("protection against Cross-Site Forgery attacks", "CSRF"),
        "public-key": ("protection to reduce success rates of MITM attacks", "MITM"),
        "content-security": ("header protection against multiple attack types", "ALL")
    }

    req, status, html, headers = get_page(url, proxy=proxy, agent=agent, xforward=xforward)

    try:
        logger.info(set_color(
            "detecting target charset..."
        ))
        charset = get_charset(url, headers)
        if charset is not None:
            logger.info(set_color(
                "target charset appears to be '{}'...".format(charset), level=25
            ))
        else:
            logger.warning(set_color(
                "unable to detect target charset...", level=30
            ))
        if identify_waf:
            waf_url = "{} {}".format(url, PROTECTION_CHECK_PAYLOAD)
            _, waf_status, waf_html, waf_headers = get_page(waf_url, xforward=xforward, proxy=proxy, agent=agent)
            logger.info(set_color(
                "checking if target URL is protected by some kind of WAF/IPS/IDS..."
            ))
            identified_waf = detect_protection(url, waf_status, waf_html, waf_headers, verbose=verbose)

            if identified_waf is None:
                logger.info(set_color(
                    "no WAF/IDS/IPS has been identified on target URL...", level=25
                ))
            else:
                logger.warning(set_color(
                    "the target URL WAF/IDS/IPS has been identified as '{}'...".format(identified_waf), level=35
                ))

        if identify_plugins:
            logger.info(set_color(
                "attempting to identify plugins..."
            ))
            identified_plugin = detect_plugins(html, headers, verbose=verbose)
            if identified_plugin is not None:
                for plugin in identified_plugin:
                    if show_description:
                        logger.info(set_color(
                            "possible plugin identified as '{}' (description: '{}')...".format(
                                plugin[0], plugin[1]
                            ), level=25
                        ))
                    else:
                        logger.info(set_color(
                            "possible plugin identified as '{}'...".format(
                                plugin[0]
                            ), level=25
                        ))
            else:
                logger.warning(set_color(
                    "no known plugins identified on target...", level=30
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
            found_headers = load_headers(url, req)
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
    except KeyboardInterrupt:
        if not pause():
            shutdown()