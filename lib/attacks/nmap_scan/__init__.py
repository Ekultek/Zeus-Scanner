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

    def send_to_file(self, data):
        """
        send all the information to a JSON file for further use
        """
        create_dir(self.dir)
        full_nmap_path = "{}/{}".format(self.dir, self.file.format(self.ip))
        with open(full_nmap_path, "a+") as log:
            log.write(data)
        return full_nmap_path

    def show_open_ports(self, json_data, sep="-" * 30):
        """
        outputs the current scan information
        """
        logger.info(set_color("finding data for IP '{}'...".format(self.ip)))
        json_data = json.loads(json_data)["scan"]
        print(
            "{}\nScanned: {} ({})\tStatus: {}\nProtocol: {}\n".format(
                sep, self.ip,
                json_data[self.ip]["hostnames"][0]["name"],
                json_data[self.ip]["status"]["state"],
                "TCP"
            )
        )
        oports = json_data[self.ip]["tcp"].keys()
        oports.sort()
        for port in oports:
            print(
                "Port: {}\tStatus: {}\tType: {}".format(
                    port, json_data[self.ip]["tcp"][port]["state"],
                    json_data[self.ip]["tcp"][port]["name"]
                )
            )
        print("{}".format(sep))


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
            json_data = data._get_all_info()
            data.show_open_ports(json_data)
            file_path = data.send_to_file(json_data)
            logger.info(set_color(
                "port scan completed, all data saved to JSON file under '{}'...".format(file_path)
            ))
        except KeyError:
            logger.fatal(set_color(
                "no port information found for '{}({})'...".format(
                    url, found_ip_address
                )
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
