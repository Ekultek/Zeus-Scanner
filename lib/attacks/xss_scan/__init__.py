import os
import re
try:
    import urlparse  # python 2
except ImportError:
    import urllib.parse as urlparse  # python 3
import tempfile
import importlib

import requests

from lib.core.errors import InvalidTamperProvided
from lib.core.settings import (
    logger,
    set_color,
    DEFAULT_USER_AGENT,
    proxy_string_to_dict,
    DBMS_ERRORS,
    create_tree,
    prompt,
    shutdown,
)


def list_tamper_scripts(path="{}/lib/tamper_scripts"):
    """
    create a list of available tamper scripts from the tamper script directory
    """
    retval = set()
    exclude = ["__init__.py", ".pyc"]
    for item in os.listdir(path.format(os.getcwd())):
        if not any(f in item for f in exclude):
            item = item.split(".")[0]
            item = item.split("_")[0]
            retval.add(item)
    return retval


def __tamper_payload(payload, tamper_type, warning=True, **kwargs):
    """
    add the tamper to the payload from the given tamper type
    """
    acceptable = list_tamper_scripts()
    if tamper_type in acceptable:
        tamper_name = "lib.tamper_scripts.{}_encode"
        tamper_script = importlib.import_module(tamper_name.format(tamper_type))
        return tamper_script.tamper(payload, warning=warning)
    else:
        raise InvalidTamperProvided()


def __load_payloads(filename="{}/etc/text_files/xss_payloads.txt"):
    """
    load the tamper payloads from the etc/xss_payloads file
    """
    with open(filename.format(os.getcwd())) as payloads: return payloads.readlines()


def create_urls(url, payload_list, tamper=None):
    """
    create the tampered URL's, write them to a temporary file and read them from there
    """
    tf = tempfile.NamedTemporaryFile(delete=False)
    tf_name = tf.name
    with tf as tmp:
        for i, payload in enumerate(payload_list):
            if tamper:
                try:
                    if i < 1:
                        payload = __tamper_payload(payload, tamper_type=tamper, warning=True)
                    else:
                        payload = __tamper_payload(payload, tamper_type=tamper, warning=False)
                except InvalidTamperProvided:
                    logger.error(set_color(
                        "you provided and invalid tamper script, acceptable tamper scripts are: {}...".format(
                            " | ".join(list_tamper_scripts()), level=40
                        )
                    ))
                    shutdown()
            loaded_url = "{}{}\n".format(url.strip(), payload.strip())
            tmp.write(loaded_url)
    return tf_name


def find_xss_script(url, **kwargs):
    """
    parse the URL for the given XSS payload
    """
    data = urlparse.urlparse(url)
    payload_parser = {"path": 2, "query": 4, "fragment": 5}
    if data[payload_parser["fragment"]] is not "" or None:
        retval = "{}{}".format(
            data[payload_parser["query"]], data[payload_parser["fragment"]]
        )
    else:
        retval = data[payload_parser["query"]]

    # just double checking...
    if retval == "" or None:
        retval = data[payload_parser["path"]]
    return retval


def scan_xss(url, agent=None, proxy=None):
    """
    scan the payload to see if the XSS is still present in the HTML, if it is there's a very good
    chance that the URL is vulnerable to XSS attacks. Usually what will happen is the payload will
    be tampered or encoded if the site is not vulnerable
    """
    user_agent = agent or DEFAULT_USER_AGENT
    config_proxy = proxy_string_to_dict(proxy)
    config_headers = {"connection": "close", "user-agent": user_agent}
    xss_request = requests.get(url, proxies=config_proxy, headers=config_headers)
    html_data = xss_request.content
    query = find_xss_script(url)
    for db in DBMS_ERRORS.keys():
        for item in DBMS_ERRORS[db]:
            if re.findall(item, html_data):
                return "sqli", db
    if query in html_data:
        return True, None
    return False, None


def main_xss(start_url, verbose=False, proxy=None, agent=None, tamper=None):
    """
    main attack method to be called
    """
    if tamper:
        logger.info(set_color(
            "tampering payloads with '{}'...".format(tamper)
        ))
    find_xss_script(start_url)
    logger.info(set_color(
        "loading payloads..."
    ))
    payloads = __load_payloads()
    if verbose:
        logger.debug(set_color(
            "a total of {} payloads loaded...".format(len(payloads)), level=10
        ))
    logger.info(set_color(
        "payloads will be written to a temporary file and read from there..."
    ))
    filename = create_urls(start_url, payloads, tamper=tamper)
    logger.info(set_color(
            "loaded URL's have been saved to '{}'...".format(filename)
        ))
    logger.info(set_color(
        "testing for XSS vulnerabilities on host '{}'...".format(start_url)
    ))
    if proxy is not None:
        logger.info(set_color(
            "using proxy '{}'...".format(proxy)
        ))
    success = set()
    with open(filename) as urls:
        for i, url in enumerate(urls.readlines(), start=1):
            url = url.strip()
            result = scan_xss(url, proxy=proxy, agent=agent)
            payload = find_xss_script(url)
            if verbose:
                logger.info(set_color(
                    "trying payload '{}'...".format(payload)
                ))
            if result[0] != "sqli" and result[0] is True:
                success.add(url)
                if verbose:
                    logger.debug(set_color(
                        "payload '{}' appears to be usable...".format(payload), level=10
                    ))
            elif result[0] is "sqli":
                if i <= 1:
                    logger.error(set_color(
                        "loaded URL '{}' threw a DBMS error and appears to be injectable, test for SQL injection, "
                        "backend DBMS appears to be '{}'...".format(
                            url, result[1]
                        ), level=40
                    ))
                else:
                    if verbose:
                        logger.error(set_color(
                            "SQL error discovered...", level=40
                        ))
            else:
                if verbose:
                    logger.debug(set_color(
                        "host '{}' does not appear to be vulnerable to XSS attacks with payload '{}'...".format(
                            start_url, payload
                        ), level=10
                    ))
    if len(success) != 0:
        logger.info(set_color(
            "possible XSS scripts to be used:"
        ))
        create_tree(start_url, list(success))
    else:
        logger.error(set_color(
            "host '{}' does not appear to be vulnerable to XSS attacks...".format(start_url)
        ))
    save = prompt(
        "would you like to keep the URL's saved for further testing", opts="yN"
    )
    if save.lower().startswith("n"):
        os.remove(filename)