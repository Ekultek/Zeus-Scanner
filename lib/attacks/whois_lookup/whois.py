import os
import json
import urllib2

from base64 import b64decode

from lib.core.settings import (
    WHOIS_JSON_LINK,
    write_to_log_file,
    WHOIS_RESULTS_LOG_PATH,
    logger, set_color,
    replace_http
)


def __get_encoded_string(path="{}/etc/auths/whois_auth"):
    with open(path.format(os.getcwd())) as log:
        return log.read()


def __get_n(encoded):
    return encoded.split(":")[-1]


def __decode(encoded, n):
    token = encoded.split(":")[0]
    for _ in range(0, n):
        token = b64decode(token)
    return token


def __get_token():
    encoded = __get_encoded_string()
    n = __get_n(encoded)
    token = __decode(encoded, int(n))
    return token


def gather_raw_whois_info(domain):
    """
    get the raw JSON data for from the whois API
    """
    auth_headers = {
        "Content-Type": "application/json",
        "Authorization": "Token {}".format(__get_token()),
    }
    request = urllib2.Request(
        WHOIS_JSON_LINK.format(domain), headers=auth_headers
    )
    data = urllib2.urlopen(request).read()
    _json_data = json.loads(data)
    return _json_data


def get_interesting(raw_json):
    """
    return the interesting aspects of the whois lookup from the raw JSON data
    """
    nameservers = raw_json["nameservers"]
    user_contact = raw_json["contacts"]
    admin_info = raw_json["contacts"]["admin"]
    reg_info = raw_json["registrar"]
    return nameservers, user_contact, admin_info, reg_info


def human_readable_display(domain, interesting, raw, show_readable=False):
    """
    create a human readable display from the given whois lookup
    """
    if show_readable:
        contact_dict = dict(interesting[1])
        print(" |--[!] Domain: {} (organization '{}')".format(domain, contact_dict["owner"][0]["organization"]))
        print(" |   |--[!] Found nameservers (total {})".format(len(interesting[0])))
        if len(interesting[0]) > 1:
            for i, server in enumerate(interesting[0], start=1):
                print(" |   |   |--[{}]--- {}".format(i, server))
        else:
            print(" |   |   |--{}".format("".join(interesting[0])))
        if contact_dict["owner"][0]["name"] is not None or "":
            print(" |   |--[!] Contact name found: {}".format(contact_dict["owner"][0]["name"]))
            if contact_dict["owner"][0]["phone"] != "" or None:
                print(" |   |   |-- Phone number: {}".format(contact_dict["owner"][0]["phone"]))
            else:
                print(" |   |   |-- No phone number revealed")
        else:
            print(" [x] No contact owner revealed")
        if len(contact_dict["admin"]) > 0:
            print(" |   |--[!] Total admins found {}".format(len(contact_dict["admin"])))
            for i, admin in enumerate(contact_dict["admin"]):
                print(" |   |   |--[{}]--- {}".format(i, admin))
        else:
            print(" |   |--[x] No administrators revealed")
        return write_to_log_file(raw, WHOIS_RESULTS_LOG_PATH, "whois-log-{}.json")
    else:
        return write_to_log_file(raw, WHOIS_RESULTS_LOG_PATH, "whois-log-{}.json")


def whois_lookup_main(domain, **kwargs):
    """
    main function
    """
    readable = kwargs.get("readable", False)
    verbose = kwargs.get("verbose", False)
    domain = replace_http(domain)
    logger.info(set_color(
        "performing WhoIs lookup on given domain '{}'...".format(domain)
    ))
    raw_information = gather_raw_whois_info(domain)
    logger.info(set_color(
        "discovered raw information..."
    ))
    logger.info(set_color(
        "gathering interesting information..."
    ))
    interesting_data = get_interesting(raw_information)
    if readable:
        if verbose:
            for data in interesting_data:
                if len(data) != 0 or None:
                    logger.debug(set_color(
                        "found '{}'...".format(data), level=10
                    ))
        try:
            return human_readable_display(domain, interesting_data, raw_information, show_readable=True)
        except (ValueError, Exception):
            logger.fatal(set_color(
                "unable to display any information from WhoIs lookup on domain '{}'...".format(domain), level=50
            ))
    else:
        if verbose:
            for data in interesting_data:
                if isinstance(data, dict):
                    for v in data.itervalues():
                        if len(v) != 0 or v is not None:
                            logger.debug(set_color(
                                "found '{}'...".format(v), level=10
                            ))
                elif isinstance(data, list):
                    if len(data) != 0:
                        logger.debug(set_color(
                            "found '{}'...".format(data), level=10
                        ))
        try:
            return human_readable_display(domain, interesting_data, raw_information)
        except (ValueError, Exception):
            logger.fatal(set_color(
                "unable to find any information on '{}' from WhoIs lookup...".format(domain), level=50
            ))
