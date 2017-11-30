import json
import time
import urllib2

import lib.core.common
import lib.core.settings


def gather_raw_whois_info(domain):
    """
    get the raw JSON data for from the whois API
    """
    auth_headers = {
        lib.core.common.HTTP_HEADER.CONTENT_TYPE: "application/json",
        lib.core.common.HTTP_HEADER.AUTHORIZATION: "Token {}".format(lib.core.settings.get_token(lib.core.settings.WHOIS_AUTH_PATH)),
    }
    request = urllib2.Request(
        lib.core.settings.WHOIS_JSON_LINK.format(domain), headers=auth_headers
    )
    data = urllib2.urlopen(request).read()
    _json_data = json.loads(data)
    return _json_data


def _pretty_print_json(data, sort=True, indentation=4):
    return json.dumps(data, sort_keys=sort, indent=indentation)


def get_interesting(raw_json):
    """
    return the interesting aspects of the whois lookup from the raw JSON data
    """
    nameservers = raw_json["nameservers"]
    user_contact = raw_json["contacts"]
    reg_info = raw_json["registrar"]
    return nameservers, user_contact, reg_info


def human_readable_display(domain, interesting):
    """
    create a human readable display from the given whois lookup
    """
    data_sep = "-" * 30
    servers, contact, reg = interesting
    total_servers, total_contact, total_reg = len(servers), len(contact), len(reg)
    print(data_sep)
    print("[!] Domain {}".format(domain))
    if total_servers > 0:
        print("[!] Found a total of {} servers".format(total_servers))
        print(_pretty_print_json(servers))
    else:
        print("[x] No server information found")
    if total_contact > 0:
        print("[!] Found contact information")
        print(_pretty_print_json(contact))
    else:
        print("[x] No contact information found")
    if total_reg > 0:
        print("[!] Found register information")
        print(_pretty_print_json(reg))
    else:
        print("[x] No register information found")
    print(data_sep)


def whois_lookup_main(domain, **kwargs):
    """
    main function
    """
    # sleep a little bit so that WhoIs doesn't stop us from making requests
    verbose = kwargs.get("verbose", False)
    timeout = kwargs.get("timeout", None)
    domain = lib.core.settings.replace_http(domain)

    try:
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "performing WhoIs lookup on given domain '{}'...".format(domain)
        ))
        if timeout is not None:
            time.sleep(timeout)
        try:
            raw_information = gather_raw_whois_info(domain)
        except Exception:
            lib.core.settings.logger.error(lib.core.settings.set_color(
                "unable to produce information from WhoIs lookup...", level=40
            ))
            return None
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "discovered raw information...", level=25
        ))
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "gathering interesting information..."
        ))
        interesting_data = get_interesting(raw_information)
        if verbose:
            try:
                human_readable_display(domain, interesting_data)
            except (ValueError, Exception):
                lib.core.settings.logger.error(lib.core.settings.set_color(
                    "unable to display any information from WhoIs lookup on domain '{}'...".format(domain), level=50
                ))
                return None
        lib.core.common.write_to_log_file(
            raw_information, lib.core.settings.WHOIS_RESULTS_LOG_PATH,
            lib.core.settings.WHOIS_LOOKUP_FILENAME.format(domain)
        )
    except KeyboardInterrupt:
        if not lib.core.common.pause():
            lib.core.common.shutdown()