import os
import io
import re
import sys
import glob
import json
import time
import shlex
import difflib
import logging
import string
import random
import subprocess

try:
    import ConfigParser  # python 2
except ImportError:
    import configparser as ConfigParser  # python 3

import psutil
import requests

import bin.unzip_gecko
import lib.core.errors

from lib.attacks.sqlmap_scan.sqlmap_opts import SQLMAP_API_OPTIONS
from lib.attacks.nmap_scan.nmap_opts import NMAP_API_OPTS

try:
    raw_input  # Python 2
except NameError:
    raw_input = input  # Python 3

# get the master patch ID when a patch is pushed to the program
PATCH_ID = str(subprocess.check_output(["git", "rev-parse", "origin/master"]))[:6]
# clone link
CLONE = "https://github.com/ekultek/zeus-scanner.git"
# current version <major.minor.commit.patch ID>
VERSION = "1.1.2.{}".format(PATCH_ID)
# colors to output depending on the version
VERSION_TYPE_COLORS = {"dev": 33, "stable": 92, "other": 30}
# version string formatting
if VERSION.count(".") == 1:
    VERSION_STRING = "\033[92mv{}\033[0m(\033[{}m\033[1mstable\033[0m)".format(VERSION, VERSION_TYPE_COLORS["stable"])
elif VERSION.count(".") <= 2:
    VERSION_STRING = "\033[92mv{}\033[0m(\033[{}m\033[1mdev\033[0m)".format(VERSION, VERSION_TYPE_COLORS["dev"])
else:
    VERSION_STRING = "\033[92mv{}\033[0m(\033[{}m\033[1mrevision\033[0m)".format(VERSION, VERSION_TYPE_COLORS["other"])
# zeus-scanners saying
SAYING = "Advanced Dork Searching..."
# sexy banner
BANNER = """\033[36m
    __          __________                             __   
   / /          \____    /____  __ __  ______          \ \  
  / /    ______   /     // __ \|  |  \/  ___/  ______   \ \ 
  \ \   /_____/  /     /\  ___/|  |  /\___ \  /_____/   / / 
   \_\          /_______ \___  >____//____  >          /_/  
                       \/   \/           \/  {}
\t{}\n\t\t{}\033[0m""".format(VERSION_STRING, CLONE, SAYING)
# default user agent if another one isn't given
DEFAULT_USER_AGENT = "Zeus-Scanner(v{})::Python->v{}.{}".format(
    VERSION, sys.version_info[0], sys.version_info[1]
)
# regex to find GET params in a URL, IE php?id=
URL_QUERY_REGEX = re.compile(r"(.*)[?|#](.*){1}\=(.*)")
# regex to recognize a URL
URL_REGEX = re.compile(r"((https?):((//)|(\\\\))+([\w\d:#@%/;$()~_?\+-=\\\.&](#!)?)*)")
# path to the checksum
CHECKSUM_PATH = "{}/etc/checksum/md5sum.md5".format(os.getcwd())
# geckodriver version information path, grabs the file that was installed on your system
GECKO_VERSION_INFO_PATH = "{}/bin/version_info".format(os.getcwd())
# attempt to fix the program install error
FIX_PROGRAM_INSTALL_PATH = "{}/etc/scripts/fix_pie.sh".format(os.getcwd())
# path to the auto clean tool
CLEANUP_TOOL_PATH = "{}/etc/scripts/cleanup.sh".format(os.getcwd())
# path to tool to launch sqlmap API
LAUNCH_SQLMAP_API_TOOL = "{}/etc/scripts/launch_sqlmap_api.sh".format(os.getcwd())
# path to nmap installer
NMAP_INSTALLER_TOOL = "{}/etc/scripts/install_nmap.sh".format(os.getcwd())
# paths to sqlmap and nmap
TOOL_PATHS = "{}/bin/paths/path_config.ini".format(os.getcwd())
# log path to the whois results
WHOIS_RESULTS_LOG_PATH = "{}/log/whois".format(os.getcwd())
# path to store robot.txt page in
ROBOTS_PAGE_PATH = "{}/log/robots".format(os.getcwd())
# URL's that are extracted from Google's ban URL
EXTRACTED_URL_LOG = "{}/log/extracted-url-log".format(os.getcwd())
# log path for the URL's that are found
URL_LOG_PATH = "{}/log/url-log".format(os.getcwd())
# log path for port scans
PORT_SCAN_LOG_PATH = "{}/log/scanner-log".format(os.getcwd())
# blackwidow log path
SPIDER_LOG_PATH = "{}/log/blackwidow-log".format(os.getcwd())
# the current log file being used
CURRENT_LOG_FILE_PATH = "{}/log".format(os.getcwd())
# nmap's manual page for their options
NMAP_MAN_PAGE_URL = "https://nmap.org/book/man-briefoptions.html"
# sqlmap's manual page for their options
SQLMAP_MAN_PAGE_URL = "https://github.com/sqlmapproject/sqlmap/wiki/Usage"
# whois API link
WHOIS_JSON_LINK = "https://jsonwhoisapi.com/api/v1/whois?identifier={}"
# holder for sqlmap API ID hashes, makes it so that they are all unique
ALREADY_USED = set()
# search engines that the application can use
AUTHORIZED_SEARCH_ENGINES = {
    "aol": "http://aol.com",
    "bing": "http://bing.com",
    "duckduckgo": "http://duckduckgo.com",
    "google": "http://google.com"
}
# extensions to exclude from the spider
SPIDER_EXT_EXCLUDE = (
    "3ds", "3g2", "3gp", "7z", "DS_Store",
    "a", "aac", "adp", "ai", "aif", "aiff",
    "apk", "ar", "asf", "au", "avi", "bak",
    "bin", "bk", "bmp", "btif", "bz2", "cab",
    "caf", "cgm", "cmx", "cpio", "cr2", "dat",
    "deb", "djvu", "dll", "dmg", "dmp", "dng",
    "doc", "docx", "dot", "dotx", "dra", "dsk",
    "dts", "dtshd", "dvb", "dwg", "dxf", "ear",
    "ecelp4800", "ecelp7470", "ecelp9600", "egg",
    "eol", "eot", "epub", "exe", "f4v", "fbs", "fh",
    "fla", "flac", "fli", "flv", "fpx", "fst", "fvt",
    "g3", "gif", "gz", "h261", "h263", "h264", "ico",
    "ief", "image", "img", "ipa", "iso", "jar", "jpeg",
    "jpg", "jpgv", "jpm", "jxr", "ktx", "lvp", "lz",
    "lzma", "lzo", "m3u", "m4a", "m4v", "mar", "mdi",
    "mid", "mj2", "mka", "mkv", "mmr", "mng", "mov",
    "movie", "mp3", "mp4", "mp4a", "mpeg", "mpg",
    "mpga", "mxu", "nef", "npx", "o", "oga", "ogg",
    "ogv", "otf", "pbm", "pcx", "pdf", "pea", "pgm",
    "pic", "png", "pnm", "ppm", "pps", "ppt", "pptx",
    "ps", "psd", "pya", "pyc", "pyo", "pyv", "qt", "rar",
    "ras", "raw", "rgb", "rip", "rlc", "rz", "s3m", "s7z",
    "scm", "scpt", "sgi", "shar", "sil", "smv", "so", "sub",
    "swf", "tar", "tbz2", "tga", "tgz", "tif", "tiff", "tlz",
    "ts", "ttf", "uvh", "uvi", "uvm", "uvp", "uvs", "uvu",
    "viv", "vob", "war", "wav", "wax", "wbmp", "wdp", "weba",
    "webm", "webp", "whl", "wm", "wma", "wmv", "wmx", "woff",
    "woff2", "wvx", "xbm", "xif", "xls", "xlsx", "xlt", "xm",
    "xpi", "xpm", "xwd", "xz", "z", "zip", "zipx"
)
# urls to exclude from being grabbed during the searching
URL_EXCLUDES = (
    "maps.google", "play.google", "youtube",
    "drive.google", "books.google", "news.google",
    "www.google", "mail.google", "accounts.google",
    "schema.org", "www.<b", "https://cid-", "https://<strong",  # these are some weird things that get pulled up?
    "plus.google"
)
# regular expressions used for DBMS recognition based on error message response
DBMS_ERRORS = {
    "MySQL": (r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"valid MySQL result", r"MySqlClient\."),
    "PostgreSQL": (r"PostgreSQL.*ERROR", r"Warning.*\Wpg_.*", r"valid PostgreSQL result", r"Npgsql\."),
    "Microsoft SQL Server": (r"Driver.* SQL[\-\_\ ]*Server", r"OLE DB.* SQL Server",
                             r"(\W|\A)SQL Server.*Driver", r"Warning.*mssql_.*",
                             r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
                             r"(?s)Exception.*\WSystem\.Data\.SqlClient\.", r"(?s)Exception.*\WRoadhouse\.Cms\."),
    "Microsoft Access": (r"Microsoft Access Driver", r"JET Database Engine", r"Access Database Engine"),
    "Oracle": (r"\bORA-[0-9][0-9][0-9][0-9]", r"Oracle error", r"Oracle.*Driver",
               r"Warning.*\Woci_.*", r"Warning.*\Wora_.*"),
    "IBM DB2": (r"CLI Driver.*DB2", r"DB2 SQL error", r"\bdb2_\w+\("),
    "SQLite": (r"SQLite/JDBCDriver", r"SQLite.Exception",
               r"System.Data.SQLite.SQLiteException", r"Warning.*sqlite_.*",
               r"Warning.*SQLite3::", r"\[SQLITE_ERROR\]"),
    "Sybase": (r"(?i)Warning.*sybase.*", r"Sybase message", r"Sybase.*Server message.*"),
}


# this has to be the first function so that I can use it in the logger settings below
def create_log_name(log_path="{}/log", filename="zeus-log-{}.log"):
    """
    create the current log file name by figuring out how many files are there
    """
    if not os.path.exists(log_path.format(os.getcwd())):
        os.mkdir(log_path.format(os.getcwd()))
    find_file_amount = len(os.listdir(log_path.format(os.getcwd())))
    full_log_path = "{}/{}".format(log_path.format(os.getcwd()), filename.format(find_file_amount + 1))
    return full_log_path


# console logger and file logger settings
logger = logging.getLogger("zeus-log")
logger.setLevel(logging.DEBUG)
file_handler = logging.FileHandler(
    filename=create_log_name(), mode="a+"
)
file_handler.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
file_format = logging.Formatter(
    '%(asctime)s;%(name)s;%(levelname)s;%(message)s'
)
console_format = logging.Formatter(
    "[%(asctime)s %(levelname)s] %(message)s", "%H:%M:%S"
)
file_handler.setFormatter(file_format)
console_handler.setFormatter(console_format)
logger.addHandler(console_handler)
logger.addHandler(file_handler)


def create_dir(dirpath):
    """
    create a directory if it doesn't exist
    """
    if not os.path.exists(dirpath):
        os.mkdir(dirpath)


def find_running_opts(options):
    """
    display the running options if verbose is used
    """
    opts_being_used = []
    for o, v in options.__dict__.iteritems():
        if v is not None:
            opts_being_used.append((o, v))
    return dict(opts_being_used)


def set_color(org_string, level=None):
    """
    set the console log color, this will kinda mess with the file log but whatever
    """
    color_levels = {
        10: "\033[36m{}\033[0m",  # DEBUG
        20: "\033[32m{}\033[0m",  # INFO *default
        30: "\033[33m{}\033[0m",  # WARNING
        40: "\033[31m{}\033[0m",  # ERROR
        50: "\033[7;31;31m{}\033[0m"  # FATAL/CRITICAL/EXCEPTION
    }
    if level is None:
        return color_levels[20].format(org_string)
    else:
        return color_levels[int(level)].format(org_string)


def get_proxy_type(proxy_string):
    """
    get the type of proxy that is being used or output possible proxy types you're trying to use
    """
    acceptable = ("http", "https", "socks5", "socks4")
    prox_list = proxy_string.split("://")
    if prox_list[0] not in acceptable:
        raise lib.core.errors.InvalidProxyType(
            "{} is not a valid proxy type, you might be looking for "
            "{}..".format(prox_list[0], difflib.get_close_matches(prox_list[0], acceptable))
        )
    else:
        return prox_list[0], prox_list[-1]


def proxy_string_to_dict(proxy_string):
    """
    send the proxy string to a dict -> http://127.0.0.1:8080 -> {'http': '127.0.0.1:8080'}
    """
    if proxy_string is None:
        return None
    proxy_data = get_proxy_type(proxy_string)
    retval = {proxy_data[0]: proxy_data[1]}
    return retval


def start_up():
    """
    start the program and display the time it was started
    """
    print(
        "\n\n[*] starting up at {}..\n\n".format(time.strftime("%H:%M:%S"))
    )


def shutdown():
    """
    shut down the program and the time it stopped
    """
    print(
        "\n\n[*] shutting down at {}..\n\n".format(time.strftime("%H:%M:%S"))
    )
    exit(0)


def setup(verbose=False):
    """
    setup the application if it has not been setup yet
    """
    if verbose:
        logger.debug(set_color(
            "checking if the application has been run before...", level=10
        ))
    bin.unzip_gecko.main(verbose=verbose)


def get_latest_log_file(log_path):
    """
    get the latest log file being used from the given path
    """
    file_list = glob.glob(log_path + "/*")
    try:
        latest = max(file_list, key=os.path.getctime)
        return latest
    except ValueError:
        return None


def replace_http(url, queries=True, complete=False):
    """
    replace the http in the url so we can get the IP address
    """

    def __remove_queries(data):
        """
        delete the queries from the URL
        """
        return data.split("/")[0]

    try:
        url_list = url.split("//")
        new_url = url_list[1]
        if queries:
            retval = __remove_queries(new_url)
        elif complete:
            retval = __remove_queries(new_url)
            if "www" in retval:
                retval = retval.replace("www.", "")
        return retval
    except IndexError:
        return url


def grab_random_agent(agent_path="{}/etc/agents.txt", verbose=False):
    """
    grab a random user agent from the agent file
    """
    if verbose:
        logger.debug(set_color(
            "grabbing random user-agent from '{}'...".format(agent_path.format(os.getcwd())), level=10
        ))
    with open(agent_path.format(os.getcwd())) as agents:
        retval = random.choice(agents.readlines())
        return retval.strip()


def prompt(question, opts=None):
    """
    ask a question
    """
    if opts is not None:
        options = '/'.join(opts)
        return raw_input(
            "[{} {}] {}[{}]: ".format(
                time.strftime("%H:%M:%S"),
                "PROMPT", question, options
            )
        )
    else:
        return raw_input(
            "[{} {}] {} ".format(
                time.strftime("%H:%M:%S"), "PROMPT", question
            )
        )


def find_application(application, opt="path"):
    """
    find the given application on the users system by parsing the given configuration file
    """
    retval = []
    with open(TOOL_PATHS) as config:
        read_conf = config.read()
    conf_parser = ConfigParser.RawConfigParser(allow_no_value=True)
    conf_parser.readfp(io.BytesIO(read_conf))
    for section in conf_parser.sections():
        if str(section).lower() == str(application).lower():
            retval.append(conf_parser.get(section, opt))
    return retval


def get_random_dork(filename="{}/etc/dorks.txt"):
    """
    grab a random dork from the file
    """
    with open(filename.format(os.getcwd())) as dorks:
        return random.choice(dorks.readlines())


def update_zeus():
    """
    update zeus to the newest version
    """
    can_update = True if ".git" in os.listdir(os.getcwd()) else False
    if can_update:
        return os.system("git pull origin master")
    else:
        logger.fatal(set_color(
            "no git repository found in directory, unable to update automatically..."
        ))


def create_tree(start, conns, down="|", over="-", sep="-" * 40):
    """
    create a tree of connections made, will be used for things like XSS and admin pages
    """
    print("{}\nStarting URL: {}\n\nConnections:".format(sep, start))
    for con in conns:
        print(
            "{}{}{}".format(
                down, over, con
            )
        )
    print(sep)


def get_true_url(url):
    """
    get the true URL of an otherwise messy URL
    """
    data = url.split("/")
    return "{}//{}".format(data[0], data[2])


def fix_log_file(logfile=get_latest_log_file(CURRENT_LOG_FILE_PATH)):
    """
    fix the log file, the way the color is set causes the log file to get code escapes (\033),
    this will delete them out of the file
    """
    retval = ""
    escape_seq_regex = re.compile("\033\[\d+[*m]")
    with open(logfile, "r+") as to_fix:
        for line in to_fix.readlines():
            retval += escape_seq_regex.sub("", line)
    open(logfile, "w").close()
    with open(logfile, "a+") as fixed:
        for line in retval.split("\n"):
            fixed.write(line + "\n")


def write_to_log_file(data_to_write, path, filename):
    """
    write all found data to a log file
    """
    create_dir(path.format(os.getcwd()))
    full_file_path = "{}/{}".format(
        path.format(os.getcwd()), filename.format(len(os.listdir(path.format(
            os.getcwd()
        ))) + 1)
    )
    with open(full_file_path, "a+") as log:
        if isinstance(data_to_write, list):
            for item in data_to_write:
                item = item.strip()
                log.write(str(item) + "\n")
        elif isinstance(data_to_write, (tuple, set)):
            for item in list(data_to_write):
                item = item.strip()
                log.write(str(item) + "\n")
        elif isinstance(data_to_write, dict):
            json.dump(data_to_write, log, sort_keys=True, indent=4)
        else:
            log.write(data_to_write + "\n")
    logger.info(set_color(
        "successfully wrote found items to '{}'...".format(full_file_path)
    ))
    return full_file_path


def search_for_process(name):
    """
    search for a given process to see if it's started or not
    """
    all_process_names = set()
    for pid in psutil.pids():
        process = psutil.Process(pid)
        all_process_names.add(" ".join(process.cmdline()).strip())
    return False if not any(name in proc for proc in list(all_process_names)) else True


def get_browser_version():
    """
    obtain the firefox browser version, this is necessary because zeus can only handle certain versions.
    """
    logger.info(set_color(
        "attempting to get firefox browser version..."
    ))
    try:
        firefox_version_command = shlex.split("firefox --version")
        output = subprocess.check_output(firefox_version_command)
    except (OSError, Exception):
        logger.error(set_color(
            "failed to run firefox...", level=50
        ))
        return "failed to start"
    try:
        major, minor = map(int, re.search(r"(\d+).(\d+)", output).groups())
    except (ValueError, Exception):
        logger.error(set_color(
            "failed to parse '{}' for version number...".format(output), level=50
        ))
        return "failed to gather"
    return major, minor


def config_headers(**kwargs):
    """
    configure the request headers, this will configure user agents and proxies
    """
    proxy = kwargs.get("proxy", None)
    rand_proxy = kwargs.get("proxy_file", None)
    personal_agent = kwargs.get("p_agent", None)
    rand_agent = kwargs.get("rand_agent", None)
    verbose = kwargs.get("verbose", False)
    if proxy is not None:
        proxy_retval = proxy
    elif rand_proxy is not None:
        if verbose:
            logger.debug(set_color(
                "loading random proxy from '{}'...".format(rand_proxy), level=10
            ))
        with open(rand_proxy) as proxies:
            possible = proxies.readlines()
            proxy_retval = random.choice(possible).strip()
    else:
        proxy_retval = None
    if personal_agent is not None:
        agent = personal_agent
    elif rand_agent:
        agent = grab_random_agent(verbose=verbose)
    else:
        agent = DEFAULT_USER_AGENT
    return proxy_retval, agent


def get_md5sum(url="https://raw.githubusercontent.com/Ekultek/Zeus-Scanner/master/etc/checksum/md5sum.md5"):
    """
    compare the checksums to post an issue
    """
    current_checksum = open(CHECKSUM_PATH).read()
    posted_checksum = requests.get(url).content
    if current_checksum == posted_checksum:
        return True


def create_identifier(chars=string.ascii_letters):
    """
    create the identifier for your Github issue
    """
    retval = []
    for _ in range(0, 7):
        retval.append(random.choice(chars))
    return "".join(retval)


def config_search_engine(**kwargs):
    """
    configure the search engine if a one different from google is given
    """
    verbose = kwargs.get("verbose", False)
    aol = kwargs.get("aol", False)
    bing = kwargs.get("bing", False)
    ddg = kwargs.get("ddg", False)
    enum = kwargs.get("enum", None)

    non_default_msg = "specified to use non-default search engine..."
    se_message = "using '{}' as the search engine..."
    if ddg:
        if verbose:
            logger.debug(set_color(
                se_message.format("DuckDuckGo"), level=10
            ))
        logger.info(set_color(
            non_default_msg
        ))
        se = AUTHORIZED_SEARCH_ENGINES["duckduckgo"]
    elif aol:
        logger.warning(set_color(
            "AOL will take a little longer due to pop-ups...", level=30
        ))
        if verbose:
            logger.debug(set_color(
                se_message.format("AOL"), level=10
            ))
        logger.info(set_color(
            non_default_msg
        ))
        se = AUTHORIZED_SEARCH_ENGINES["aol"]
    elif bing:
        if verbose:
            logger.debug(set_color(
                se_message.format("Bing"), level=10
            ))
        logger.info(set_color(
            non_default_msg
        ))
        se = AUTHORIZED_SEARCH_ENGINES["bing"]
    else:
        if verbose:
            logger.debug(set_color(
                "using default search engine (Google)...", level=10
            ))
        logger.info(set_color(
            "using default search engine..."
        )) if enum is None else ""
        se = AUTHORIZED_SEARCH_ENGINES["google"]
    return se


def create_arguments(**kwargs):
    """
    create the arguments for sqlmap and nmap if arguments are passed
    """
    nmap = kwargs.get("nmap", False)
    sqlmap = kwargs.get("sqlmap", False)
    sqlmap_args = kwargs.get("sqlmap_args", None)
    nmap_args = kwargs.get("nmap_args", None)

    logger.info(set_color(
        "creating arguments for {}...".format("sqlmap" if sqlmap else "nmap")
    ))
    retval = []
    splitter = {"sqlmap": ",", "nmap": "|"}
    if sqlmap:
        warn_msg = "option '{}' is not recognized by sqlmap API, skipping..."
        if sqlmap_args is not None:
            for line in sqlmap_args.split(splitter["sqlmap"]):
                try:
                    to_use = line.strip().split(" ")
                    option = (to_use[0], to_use[1])
                    if to_use[0] in SQLMAP_API_OPTIONS:
                        retval.append(option)
                    else:
                        logger.warning(set_color(
                            warn_msg.format(option[0]),
                            level=30
                        ))
                except IndexError:
                    option = (line.strip(), "true")
                    if line.strip() in SQLMAP_API_OPTIONS:
                        retval.append(option)
                    else:
                        logger.warning(set_color(
                            warn_msg.format(line.strip()), level=30
                        ))

    elif nmap:
        warning_msg = "option {} is not known by the nmap api, skipping..."
        if nmap_args is not None:
            for line in nmap_args.split(splitter["nmap"]):
                try:
                    data = line.index(" ")
                except Exception:
                    data = None
                    pass
                if data is not None:
                    argument = line[0:data]
                    if argument in NMAP_API_OPTS:
                        retval.append(line)
                    else:
                        logger.warning(set_color(
                            warning_msg.format(argument), level=30
                        ))
                else:
                    if line in NMAP_API_OPTS:
                        retval.append(line)
                    else:
                        logger.warning(set_color(
                            warning_msg.format(line), level=30
                        ))
    return retval
