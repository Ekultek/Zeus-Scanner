import json

import requests
from xml.dom import minidom

from lib.core.settings import (
    logger, set_color,
    HEADER_XML_DATA,
    proxy_string_to_dict,
    create_random_ip,
    write_to_log_file,
    HEADER_RESULT_PATH,
    replace_http,
    PROTECTED
)


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
            "connection": "close",
            "user-agent": agent
        }
    else:
        ip_list = create_random_ip(), create_random_ip(), create_random_ip()
        header_value = {
            "connection": "close",
            "user-agent": agent,
            "X-Forwarded-For": "{}, {}, {}".format(
                ip_list[0], ip_list[1], ip_list[2]
            )
        }
    req = requests.get(url, params=header_value, proxies=proxy)
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

    protection = {}
    definition = {
        "x-xss": ("protection against XSS attacks", "XSS"),
        "strict-transport": ("protection against unencrypted connections (force HTTPS connection)", "HTTPS"),
        "x-frame": ("protection against clickjacking vulnerabilities", "CLICKJACKING"),
        "x-content": ("protection against MIME type attacks", "MIME"),
        "content-security": ("protection against multiple attacks", "ALL")
    }
    if verbose:
        logger.debug(set_color(
            "loading XML data...", level=10
        ))
    comparable_headers = load_xml_data(HEADER_XML_DATA)
    logger.info(set_color(
        "attempting to get request headers..."
    ))
    found_headers = load_headers(url, proxy=proxy, agent=agent, xforward=xforward)
    if verbose:
        logger.debug(set_color(
            "fetched {}...".format(found_headers), level=10
        ))
    headers_established = [str(h) for h in compare_headers(found_headers, comparable_headers)]
    protection["target"] = url
    for key in definition.iterkeys():
        if any(key in h.lower() for h in headers_established):
            logger.error(set_color(
                "provided target has {}...".format(definition[key][0]), level=40
            ))
            protection[key] = True
            PROTECTED.add(definition[key][1])
        else:
            logger.info(set_color(
                "provided target does not have {}...".format(definition[key][0])
            ))
            protection[key] = False
    data_to_write = json.dumps(protection, indent=4)
    write_to_log_file(data_to_write, HEADER_RESULT_PATH, "{}-headers.json".format(replace_http(url)))
