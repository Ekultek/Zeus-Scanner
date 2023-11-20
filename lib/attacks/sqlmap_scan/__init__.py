import json
import re
import subprocess
import shlex
import urllib.request as urllib2
import requests

import lib.core.common
import lib.core.settings
import lib.core.errors
import lib.attacks

from var.auto_issue.github import request_issue_creation


class SqlmapHook(object):

    """
    Sqlmap API hook, will process API requests, and output API data
    """

    def __init__(self, to_scan, port=None, api_con="http://127.0.0.1:{}", default_port=8775):
        self.to_scan = to_scan
        self.port = port or default_port
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
        Create a new API scan
        """
        new_scan_url = "{}{}".format(self.connection, self.commands["init"])
        return requests.get(new_scan_url, params=self.headers)

    def get_scan_id(self, split_by=16):
        """
        Get the ID of the current API scan
        """
        current_scan_id = None
        id_re = re.compile(r"[a-fA-F0-9]{16}")
        api_id_url = "{}{}".format(self.connection, self.commands["id"])
        req = requests.get(api_id_url)
        to_check = str(json.loads(req.content)["tasks"]).lower()
        found = ''.join(id_re.findall(to_check))
        if len(found) > 16:
            # split the found ID by 16 characters each time one is found to be over 16 characters
            # IE ['abcdee345593fffa', '2222aaa449837cc9']
            # if any of these items are not in the already used container, then chances are that's the
            # item we're looking for.
            # this will also allow you to go back to the same item more then once.
            data_found = [found[i:i+split_by] for i in range(0, len(found), split_by)]
            for item in data_found:
                if item not in lib.core.settings.ALREADY_USED:
                    lib.core.settings.ALREADY_USED.add(item)
                    current_scan_id = item
        else:
            lib.core.settings.ALREADY_USED.add(found)
            current_scan_id = found
        return current_scan_id

    def start_scan(self, api_id, opts=None):
        """
        Start the API scan
        """
        start_scan_url = "{}{}".format(self.connection, self.commands["start"].format(api_id))
        data_dict = {"url": self.to_scan}
        if opts is not None:
            for i in range(0, len(opts)):
                # if the options are passed they will be placed as a dict
                # IE {'level': 5, 'risk': 3}
                # from there they will be added into the post data dict what this
                # will accomplish is that it will take precedence over the already
                # set data on the sqlmap API client and replace that data with the
                # data that is provided.
                # IE
                # {
                #   'level': 1,
                #   'risk': 1,
                # }
                # will become
                # {
                #   'level': '5',
                #   'risk': '3',
                # }
                data_dict[opts[i][0]] = opts[i][1]
        post_data = json.dumps(data_dict)
        req = urllib2.Request(start_scan_url, data=str.encode(post_data), headers=self.headers)
        return urllib2.urlopen(req)

    def show_sqlmap_log(self, api_id):
        """
        Show the sqlmap log during the API scan
        """
        running_status_url = "{}{}".format(self.connection, self.commands["status"].format(api_id))
        running_log_url = "{}{}".format(self.connection, self.commands["log"].format(api_id))
        status_req = requests.get(running_status_url)
        status_json = json.loads(status_req.content)
        current_status = status_json["status"]
        if current_status != "running":
            raise lib.core.errors.SqlmapFailedStart(
                "sqlmap API failed to start the run, check the client and see what "
                "the problem is and try again"
            )
        already_displayed = set()
        while current_status == "running":
            # while the current status evaluates to `running`
            # we can load the JSON data and output the log information
            # we will skip over information that has already been provided
            # by using the already displayed container set.
            # this will allow us to only output information that we
            # have not seen yet.
            current_status = json.loads(requests.get(running_status_url).content)["status"]
            log_req = requests.get(running_log_url)
            log_json = json.loads(log_req.content)
            for i in range(0, len(log_json["log"])):
                if log_json["log"][i]["message"] in already_displayed:
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


def find_sqlmap(to_find="sqlmap"):
    """
    Find sqlmap on the users system
    """
    found_path = lib.core.settings.find_application(to_find)
    return found_path


def sqlmap_scan_main(url, port=None, verbose=None, opts=None, auto_start=False):
    """
    The main function that will be called and initialize everything
    """

    is_started = lib.core.settings.search_for_process("sqlmapapi.py")
    found_path = find_sqlmap()

    if auto_start:
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "Attempting to launch sqlmap API"
        ))
        sqlmap_api_command = shlex.split("sudo sh {} p {}".format(
            lib.core.settings.LAUNCH_SQLMAP_API_TOOL, "".join(found_path)
        ))
        subprocess.Popen(sqlmap_api_command, stdout=subprocess.PIPE)
        if is_started:
            lib.core.settings.logger.info(lib.core.settings.set_color(
                "sqlmap API is up and running, continuing process"
            ))
        else:
            lib.core.settings.logger.error(lib.core.settings.set_color(
                "There was a problem starting sqlmap API", level=40
            ))
            lib.core.common.prompt(
                "Manually start the API and press enter when ready"
            )
    else:
        if not is_started:
            lib.core.common.prompt(
                "sqlmap API is not started, start it and press enter to continue"
            )
    try:
        sqlmap_scan = SqlmapHook(url, port=port)
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "Initializing new sqlmap scan with given URL '{}'".format(url)
        ))
        sqlmap_scan.init_new_scan()
        if verbose:
            lib.core.settings.logger.debug(lib.core.settings.set_color(
                "Scan initialized", level=10
            ))
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "Fathering sqlmap API scan ID"
        ))
        api_id = sqlmap_scan.get_scan_id()
        if verbose:
            lib.core.settings.logger.debug(lib.core.settings.set_color(
                "Current sqlmap scan ID: '{}'".format(api_id), level=10
            ))
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "Starting sqlmap scan on url: '{}'".format(url), level=25
        ))
        if opts:
            if verbose:
                lib.core.settings.logger.debug(lib.core.settings.set_color(
                    "Using arguments: '{}'".format(opts), level=10
                ))
            lib.core.settings.logger.info(lib.core.settings.set_color(
                "Adding arguments to sqlmap API"
            ))
        else:
            if verbose:
                lib.core.settings.logger.debug(lib.core.settings.set_color(
                    "No arguments passed, skipping", level=10
                ))
        lib.core.settings.logger.warning(lib.core.settings.set_color(
            "Please keep in mind that this is the API, output will "
            "not be saved to log file, it may take a little longer "
            "to finish processing, launching sqlmap", level=30
        ))
        sqlmap_scan.start_scan(api_id, opts=opts)
        print("-" * 30)
        sqlmap_scan.show_sqlmap_log(api_id)
        print("-" * 30)
    except requests.exceptions.HTTPError as e:
        lib.core.settings.logger.exception(lib.core.settings.set_color(
            "Ran into error '{}', seems you didn't start the server, check "
            "the server port and try again".format(e), level=50
        ))
        pass
    except KeyboardInterrupt:
        if not lib.core.common.pause():
            lib.core.common.shutdown()
    except Exception as e:
        if "HTTPConnectionPool(host='127.0.0.1'" in str(e):
            lib.core.settings.logger.error(lib.core.settings.set_color(
                "sqlmap API is not started, did you forget to start it? "
                "You will need to open a new terminal, cd into sqlmap, and "
                "run `python3 sqlmapapi.py -s` otherwise pass the correct flags "
                "to auto start the API", level=40
            ))
            pass
        else:
            lib.core.settings.logger.exception(lib.core.settings.set_color(
                "Ran into error '{}', seems something went wrong, error has "
                "been saved to current log file.".format(e), level=50
            ))
            request_issue_creation()
            pass
