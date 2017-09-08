import re
import json
import time
import urllib2
import subprocess

import requests

import lib.settings
import lib.errors


class SqlmapHook(object):

    """
    Sqlmap API hook, will process API requests, and output API data
    """

    def __init__(self, to_scan, port=None, api_con="http://127.0.0.1:{}", default_port=8775):
        self.to_scan = to_scan
        if port is None:
            self.port = default_port
        else:
            self.port = port
        self.headers = {"Content-Type": "application/json"}
        self.connection = api_con.format(self.port)
        self.commands = {
            "init": "/task/new",
            "id": "/admin/0/list",
            "start": "/scan/{}/start",
            "status": "/scan/{}/status",
            "log": "/scan/{}/log"
        }

    def init_new_scan(self):
        """
        create a new API scan
        """
        new_scan_url = "{}{}".format(self.connection, self.commands["init"])
        return requests.get(new_scan_url, params=self.headers)

    def get_scan_id(self):
        """
        get the ID of the current API scan
        """
        id_re = re.compile(r"[a-fA-F0-9]{16}")
        api_id_url = "{}{}".format(self.connection, self.commands["id"])
        req = requests.get(api_id_url)
        to_check = str(json.loads(req.content)["tasks"]).lower()
        return ''.join(id_re.findall(to_check))

    def start_scan(self, api_id, opts=None):
        """
        start the API scan
        """
        start_scan_url = "{}{}".format(self.connection, self.commands["start"].format(api_id))
        data_dict = {"url": self.to_scan}
        if opts is not None:
            for i in range(0, len(opts)):
                data_dict[opts[i][0]] = opts[i][1]
        post_data = json.dumps(data_dict)
        req = urllib2.Request(start_scan_url, data=post_data, headers=self.headers)
        return urllib2.urlopen(req)

    def show_sqlmap_log(self, api_id):
        """
        show the sqlmap log during the API scan
        """
        running_status_url = "{}{}".format(self.connection, self.commands["status"].format(api_id))
        running_log_url = "{}{}".format(self.connection, self.commands["log"].format(api_id))
        status_req = requests.get(running_status_url)
        status_json = json.loads(status_req.content)
        current_status = status_json["status"]
        if current_status != "running":
            raise lib.errors.SqlmapFailedStart(
                "sqlmap API failed to start the run, check the client and see what "
                "the problem is and try again..."
            )
        already_displayed = set()
        while current_status == "running":
            current_status = json.loads(requests.get(running_status_url).content)["status"]
            log_req = requests.get(running_log_url)
            log_json = json.loads(log_req.content)
            for i in range(0, len(log_json["log"])):
                if log_json["log"][i]["message"] in already_displayed:
                    time.sleep(1)
                    pass
                else:
                    print(
                        "sqlmap> [{} {}] {}".format(
                            log_json["log"][i]["time"],
                            log_json["log"][i]["level"],
                            log_json["log"][i]["message"]
                        )
                    )
                already_displayed.add(log_json["log"][i]["message"])
                time.sleep(0.2)


def find_sqlmap(given_search_path=None, to_find="sqlmapapi.py", verbose=False):
    """
    find sqlmap on the users system
    """
    return lib.settings.find_application(to_find, verbose=verbose, given_search_path=given_search_path)


def sqlmap_scan_main(url, port=None, verbose=None, auto_search=False, opts=None, given_path=None, full_path=None):
    """
    the main function that will be called and initialize everything
    """

    def ___dict_args():
        """
        create argument tuples for the sqlmap arguments passed by the user
        """
        retval = {}
        for (arg, val) in opts:
            retval[arg] = val
        return retval

    if auto_search:
        lib.settings.logger.info(lib.settings.set_color(
            "attempting to find sqlmap on your system..."
        ))
        path = ''.join(find_sqlmap(verbose=verbose, given_search_path=given_path))
        if path:
            subprocess.check_output(["python", path, "-s"])
    else:
        lib.settings.prompt(
            "start the sqlmap API server and press enter when ready..."
        )
        try:
            sqlmap_scan = SqlmapHook(url, port=port)
            lib.settings.logger.info(lib.settings.set_color(
                "initializing new sqlmap scan with given URL '{}'...".format(url)
            ))
            sqlmap_scan.init_new_scan()
            if verbose:
                lib.settings.logger.debug(lib.settings.set_color(
                    "scan initialized...", level=10
                ))
            lib.settings.logger.info(lib.settings.set_color(
                "gathering sqlmap API scan ID..."
            ))
            api_id = sqlmap_scan.get_scan_id()
            if verbose:
                lib.settings.logger.debug(lib.settings.set_color(
                    "current sqlmap scan ID: '{}'...".format(api_id), level=10
                ))
            lib.settings.logger.info(lib.settings.set_color(
                "starting sqlmap scan on url: '{}'...".format(url)
            ))
            if opts is not None:
                if verbose:
                    lib.settings.logger.debug(lib.settings.set_color(
                        "using arguments: '{}'...".format(___dict_args()), level=10
                    ))
                lib.settings.logger.info(lib.settings.set_color(
                    "adding arguments to sqlmap API..."
                ))
            lib.settings.logger.warning(lib.settings.set_color(
                "please keep in mind that this is the API, it might take a little "
                "longer to do the full scan on the given URL... launching...", level=30
            ))
            sqlmap_scan.start_scan(api_id, opts=opts)
            print("-" * 20)
            sqlmap_scan.show_sqlmap_log(api_id)
            print("-" * 20)
        except requests.exceptions.HTTPError as e:
            lib.settings.logger.exception(lib.settings.set_color(
                "ran into error '{}', seems you didn't start the server, check "
                "the server port and try again...".format(e), level=50
            ))
            pass
        except Exception as e:
            lib.settings.logger.exception(lib.settings.set_color(
                "ran into error '{}', seems something went wrong, error has "
                "been saved to current log file. Please make an issue to get "
                "this addressed...".format(e), level=50
            ))
            pass
