import os
import re
import urlparse
import tempfile

import requests

from lib.settings import (
    logger,
    set_color,
    DEFAULT_USER_AGENT,
    proxy_string_to_dict,
    DBMS_ERRORS
)


def __load_payloads(filename="{}/etc/xss_payloads.txt"):
    with open(filename.format(os.getcwd())) as payloads: return payloads.readlines()


def create_urls(url, payload_list):
    tf = tempfile.NamedTemporaryFile(delete=False)
    tf_name = tf.name
    with tf as tmp:
        for payload in payload_list:
            loaded_url = "{}{}".format(url, payload)
            tmp.write(loaded_url)
    return tf_name


def find_xss_script(url, query=4):
    data = urlparse.urlparse(url)
    return data[query]


def scan_xss(url, agent=None, proxy=None):
    user_agent = agent or DEFAULT_USER_AGENT
    config_proxy = proxy_string_to_dict(proxy)
    config_headers = {"connection": "close", "user-agent": user_agent}
    xss_request = requests.get(url, proxies=config_proxy, headers=config_headers)
    html_data = xss_request.content
    query = find_xss_script(url)
    if str(query).lower() in str(html_data).lower():
        return True
    else:
        for db in DBMS_ERRORS.keys():
            for item in DBMS_ERRORS[db]:
                dbms_regex = re.compile(item)
                if dbms_regex.search(html_data):
                    return "sqli"
    return False


def main_xss(start_url, verbose=False, proxy=None, agent=DEFAULT_USER_AGENT, try_all=False):
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
    filename = create_urls(start_url, payloads)
    if verbose:
        logger.debug(set_color(
            "loaded URL's have been saved to '{}'...".format(filename)
        ))
    logger.info(set_color(
        "testing for XSS vulnerabilities on host '{}'...".format(start_url)
    ))
    logger.info(set_color(
        "adjusting user agent to '{}'...".format(agent)
    ))
    if proxy is not None:
        logger.info(set_color(
            "using proxy '{}'...".format(proxy)
        ))
    with open(filename) as urls:
        for url in urls:
            url = url.strip()
            result = scan_xss(url, proxy=proxy, agent=agent)
            payload = find_xss_script(url)
            if result:
                logger.info(set_color(
                    "host '{}' appears to be vulnerable to XSS attacks using payload '{}'...".format(
                        start_url, payload
                    )
                ))
                if not try_all:
                    return
            elif result is "sqli":
                logger.error(set_color(
                    "loaded URL '{}' threw a DBMS error and appears to be SQLi vulnerable, test for SQL injection".format(
                        url
                    ), level=30
                ))
            else:
                if verbose:
                    logger.debug(set_color(
                        "host '{}' does not appear to be vulnerable to XSS attacks with payload '{}'...".format(
                            start_url, payload
                        ), level=10
                    ))