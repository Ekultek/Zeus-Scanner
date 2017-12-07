import json
import socket

import nmap

import lib.core.common
import lib.core.errors
import lib.core.settings
import lib.core.decorators
from var.auto_issue.github import request_issue_creation


class NmapHook(object):

    """
    Nmap API hook, uses python, must have nmap on your system
    """

    NM = nmap.PortScanner()

    def __init__(self, ip, **kwargs):
        self.ip = ip
        self.verbose = kwargs.get("verbose", False)
        self.pretty = kwargs.get("pretty", True)
        self.dir = lib.core.settings.PORT_SCAN_LOG_PATH
        self.file = lib.core.settings.NMAP_FILENAME
        self.opts = kwargs.get("opts", "")

    def get_all_info(self):
        """
        get all the information from the scan
        """
        if isinstance(self.opts, (list, tuple)):
            self.opts = ""
        scanned_data = self.NM.scan(self.ip, arguments=self.opts)
        if self.pretty:
            scanned_data = json.dumps(scanned_data, indent=4, sort_keys=True)
        return scanned_data

    def send_to_file(self, data):
        """
        send all the information to a JSON file for further use
        """
        return lib.core.common.write_to_log_file(
            data, lib.core.settings.NMAP_LOG_FILE_PATH,
            lib.core.settings.NMAP_FILENAME.format(self.ip)
        )

    def show_open_ports(self, json_data, sep="-" * 30):
        """
        outputs the current scan information
        """
        # have to create a spacer or the output comes out funky..
        spacer_data = {4: " " * 8, 6: " " * 6, 8: " " * 4}
        lib.core.settings.logger.info(lib.core.settings.set_color("finding data for IP '{}'".format(self.ip)))
        json_data = json.loads(json_data)["scan"]
        host = json_data[self.ip]["hostnames"][0]["name"]
        host_skip = (not len(host) == 0, " ", "", None)
        print(
            "{}\nScanned: {} ({})\tStatus: {}\nProtocol: {}\n".format(
                sep, self.ip,
                host if host != any(s for s in list(host_skip)) else "unknown",
                json_data[self.ip]["status"]["state"],
                "TCP"
            )
        )
        oports = json_data[self.ip]["tcp"].keys()
        oports.sort()
        for port in oports:
            port_status = json_data[self.ip]["tcp"][port]["state"]
            # output the found port information..
            print(
                "Port: {}\tStatus: {}{}Type: {}".format(
                    port, json_data[self.ip]["tcp"][port]["state"],
                    spacer_data[len(port_status)],
                    json_data[self.ip]["tcp"][port]["name"]
                )
            )
        print("{}".format(sep))


def find_nmap(item_name="nmap"):
    """
    find nmap on the users system if they do not specify a path for it or it is not in their PATH
    """
    return lib.core.settings.find_application(item_name)


def perform_port_scan(url, scanner=NmapHook, **kwargs):
    """
    main function that will initalize the port scanning
    """
    verbose = kwargs.get("verbose", False)
    opts = kwargs.get("opts", None)
    timeout_time = kwargs.get("timeout", None)

    if timeout_time is None:
        timeout_time = 120

    with lib.core.decorators.TimeOut(seconds=timeout_time):
        lib.core.settings.logger.warning(lib.core.settings.set_color(
            "if the port scan is not completed in {}(m) it will timeout".format(
                lib.core.settings.convert_to_minutes(timeout_time)
            ), level=30
        ))
        url = url.strip()
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "attempting to find IP address for hostname '{}'".format(url)
        ))

        try:
            found_ip_address = socket.gethostbyname(url)
        except socket.gaierror:
            lib.core.settings.logger.fatal(lib.core.settings.set_color(
                "failed to gather IP address for URL '{}'".format(url)
            ))
            return

        if verbose:
            lib.core.settings.logger.debug(lib.core.settings.set_color(
                "checking for nmap on your system", level=10
            ))
        nmap_exists = "".join(find_nmap())
        if nmap_exists:
            if verbose:
                lib.core.settings.logger.debug(lib.core.settings.set_color(
                    "nmap has been found under '{}'".format(nmap_exists), level=10
                ))
            lib.core.settings.logger.info(lib.core.settings.set_color(
                "starting port scan on IP address '{}'".format(found_ip_address)
            ))
            try:
                data = scanner(found_ip_address, opts=opts)
                json_data = data.get_all_info()
                data.show_open_ports(json_data)
                file_path = data.send_to_file(json_data)
                lib.core.settings.logger.info(lib.core.settings.set_color(
                    "port scan completed, all data saved to JSON file under '{}'".format(file_path)
                ))
            except KeyError:
                lib.core.settings.logger.fatal(lib.core.settings.set_color(
                    "no port information found for '{}({})'".format(
                        url, found_ip_address
                    ), level=50
                ))
            except KeyboardInterrupt:
                if not lib.core.common.pause():
                    lib.core.common.shutdown()
            except lib.core.errors.PortScanTimeOutException:
                lib.core.settings.logger.error(lib.core.settings.set_color(
                    "port scan is taking to long and has hit the timeout, you "
                    "can increase this time by passing the --time-sec flag (IE "
                    "--time-sec 300)", level=40
                ))
            except Exception as e:
                lib.core.settings.logger.exception(lib.core.settings.set_color(
                    "ran into exception '{}', cannot continue quitting".format(e), level=50
                ))
                request_issue_creation()
                pass
        else:
            lib.core.settings.logger.fatal(lib.core.settings.set_color(
                "nmap was not found on your system", level=50
            ))
            lib.core.common.run_fix(
                "would you like to automatically install it",
                "sudo sh {}".format(lib.core.settings.NMAP_INSTALLER_TOOL),
                "nmap is not installed, please install it in order to continue"
            )