import os
import nmap
import json
import time
import socket

from lib.settings import (
    logger,
    set_color,
    create_dir,
    find_application
)


class NmapHook(object):

    """
    Nmap API hook, uses python, must have nmap on your system
    """

    NM = nmap.PortScanner()

    def __init__(self, ip, verbose=False, pretty=True,
                 dirname="{}/log/scanner-log".format(os.getcwd()), filename="nmap_scan-results-{}.json",
                 ports=None):
        self.ip = ip
        self.verbose = verbose
        self.pretty = pretty
        self.dir = dirname
        self.file = filename
        self.ports = ports

    def _get_all_info(self):
        """
        get all the information from the scan
        """
        scanned_data = self.NM.scan(self.ip, ports=self.ports)
        if self.pretty:
            scanned_data = json.dumps(scanned_data, indent=4, sort_keys=True)
        return scanned_data

    def send_to_file(self):
        """
        send all the information to a JSON file for further use
        """
        create_dir(self.dir)
        full_nmap_path = "{}/{}".format(self.dir, self.file.format(self.ip))
        with open(full_nmap_path, "a+") as log:
            log.write(self._get_all_info())
        return full_nmap_path

    def show_open_ports(self, sep="-" * 30):
        """
        outputs the current scan information
        """
        logger.info(set_color("data found for IP '{}'...".format(self.ip)))
        for host in self.NM.all_hosts():
            if host:
                print(
                    "{}\nScanned: {} ({})\nHost state: {}".format(
                        sep, self.ip, self.NM[self.ip].hostname(),
                        self.NM[self.ip].state()
                    )
                )
            else:
                logger.warning(set_color(
                    "nothing found skipping...", level=30
                ))
            for proto in self.NM[host].all_protocols():
                print(
                    "Protocol: {}".format(proto)
                )
                oports = self.NM[host][proto].keys()
                oports.sort()
                for port in oports:
                    print(
                        "Port: {}\tStatus: {}".format(
                            port, self.NM[host][proto][port]["state"]
                        )
                    )
            print(sep)


def find_nmap(item_name="nmap", given_search_path=None, verbose=False):
    """
    find nmap on the users system if they do not specify a path for it or it is not in their PATH
    """
    return find_application(item_name, given_search_path=given_search_path, verbose=verbose)


def perform_port_scan(url, ports=None, scanner=NmapHook, verbose=False, full_path=None, **kwargs):
    """
    main function that will initalize the port scanning
    """
    url = url.strip()
    logger.info(set_color(
        "attempting to find IP address for hostname '{}'...".format(url)
    ))
    found_ip_address = socket.gethostbyname(url)
    logger.info(set_color(
        "found IP address for given URL -> '{}'...".format(found_ip_address)
    ))
    if verbose:
        logger.debug(set_color(
            "checking for nmap on your system...", level=10
        ))
    nmap_exists = find_nmap(verbose=verbose)
    if nmap_exists:
        if verbose:
            logger.debug(set_color(
                "nmap has been found under '{}'...".format(nmap_exists), level=10
            ))
        logger.info(set_color(
            "starting port scan on IP address '{}'...".format(found_ip_address)
        ))
        try:
            data = scanner(found_ip_address, ports=ports)
            logger.warning(set_color(
                "sleeping for 15 seconds to given nmap time to complete...", level=30
            ))
            time.sleep(15)
            data.show_open_ports()
            file_path = data.send_to_file()
            logger.info(set_color(
                "port scan completed, saved to JSON file under '{}'...".format(file_path)
            ))
        except Exception as e:
            logger.exception(set_color(
                "ran into exception '{}', cannot continue quitting...".format(e), level=50
            ))
            pass
    else:
        logger.fatal(set_color(
            "nmap was not found on your system, please install it...", level=50
        ))
