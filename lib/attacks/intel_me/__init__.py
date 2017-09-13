import re
import socket

import lib.settings


BANNER_REGEX = re.compile("{} {}".format(lib.settings.AMT_SERVER_REGEX, lib.settings.AMT_BANNER_REGEX))


def _is_vuln(response):
    if BANNER_REGEX.search(response) is not None:
        return True
    return False


def create_connection(host, port, proxy=None, resp_size=1024):
    send_data = "GET / HTTP/1.1\r\n\r\n"
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(10)

    #if proxy is None:
    conn.connect((host, int(port)))
    #else:
    #    data_list = proxy.split("://")
    #    conn.connect(())

    conn.send(send_data)
    response = conn.recv(resp_size)
    conn.close()
    return response


def intel_amt_main(host, proxy=None, verbose=False):
    if proxy is not None:
        lib.settings.logger.warning(lib.settings.set_color(
            "proxies are not implemented yet, you will not be connected through your proxy...", level=30
        ))

    ip_address = socket.gethostbyname(host)
    lib.settings.logger.info(lib.settings.set_color(
        "checking for Intel ME AMT exploit on host '{}' IP address '{}'...".format(host, ip_address)
    ))
    for port in lib.settings.AMT_PORTS:
        if verbose:
            lib.settings.logger.debug(lib.settings.set_color(
                "checking port '{}'...".format(port), level=10
            ))

        try:
            resp = create_connection(ip_address, port, proxy=proxy)

            if _is_vuln(resp):
                lib.settings.logger.info(lib.settings.set_color(
                    "host '{}' appears to be vulnerable to AMT exploit on port '{}'...".format(host, port)
                ))
        except socket.timeout:
            lib.settings.logger.warning(lib.settings.set_color(
                "host '{}' timed out on port {}, assuming not vulnerable and proceeding...".format(host, port), level=30
            ))
            pass
        except Exception as e:
            lib.settings.logger.exception(lib.settings.set_color(
                "caught exception '{}', assuming not vulnerable and proceeding...".format(e), level=50
            ))



