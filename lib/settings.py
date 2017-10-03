import os
import re
import sys
import time
import glob
import logging
import random
import difflib
import itertools
import multiprocessing

import whichcraft

import lib.errors
import bin.unzip_gecko

try:
    raw_input          # Python 2
except NameError:
    raw_input = input  # Python 3

# clone link
CLONE = "https://github.com/ekultek/zeus-scanner.git"
# current version <major.minor.commit.patch ID>
VERSION = "1.0.27"
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
# search engines that the application can use
AUTHORIZED_SEARCH_ENGINES = {
    "aol": "http://aol.com",
    "bing": "http://bing.com",
    "duckduckgo": "http://duckduckgo.com",
    "google": "http://google.com"
}
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
DBMS_ERRORS = {  # regular expressions used for DBMS recognition based on error message response
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


def set_color(org_string, level=None):
    """
    set the console log color, this will kinda mess with the file log but whatever
    """
    color_levels = {
        10: "\033[36m{}\033[0m",       # DEBUG
        20: "\033[32m{}\033[0m",       # INFO *default
        30: "\033[33m{}\033[0m",       # WARNING
        40: "\033[31m{}\033[0m",       # ERROR
        50: "\033[7;31;31m{}\033[0m"   # FATAL/CRITICAL/EXCEPTION
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
        raise lib.errors.InvalidProxyType(
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
    latest = max(file_list, key=os.path.getctime)
    return latest


def replace_http(url):
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
        return __remove_queries(new_url)
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


def worker(filename, item):
    """
    worker for multiprocessing
    """
    if item in filename or filename == item or filename is item:
        return filename


def find_application(to_find, default_search_path="/", proc_num=25, given_search_path=None, verbose=False):
    """
    find an application on the users system if it is not in their PATH or no path is given
    """
    retval = set()
    if whichcraft.which(to_find) is None:
        logger.error(set_color(
            "{} not in your PATH, what kind of hacker are you?! "
            "defaulting to root search, this can take awhile...".format(to_find), level=40
        ))

        if verbose:
            logger.debug(set_color(
                "starting {} processes to search for '{}' starting at '{}'...".format(
                    proc_num, to_find, default_search_path if given_search_path is None else given_search_path
                ), level=10
            ))
        pool = multiprocessing.Pool(proc_num)
        walker = os.walk(default_search_path)
        file_data_gen = itertools.chain.from_iterable(
            (os.path.join(root, f) for f in files)
            for root, sub, files in walker
        )
        results = pool.map(worker, file_data_gen)
        for data in results:
            if data is not None:
                retval.add(data)
        if len(retval) == 0:
            raise lib.errors.ApplicationNotFound(
                "unable to find '{}' on your system, install it first...".format(to_find)
            )
        else:
            return list(retval)
    else:
        return whichcraft.which(to_find)


def get_random_dork(filename="{}/etc/dorks.txt"):
    """
    grab a random dork from the file
    """
    with open(filename.format(os.getcwd())) as dorks:
        return random.choice(dorks.readlines())


def update_zeus():
    can_update = True if ".git" in os.listdir(os.getcwd()) else False
    if can_update:
        return os.system("git pull origin master")
    else:
        logger.fatal(set_color(
            "no git repository found in directory, unable to update automatically..."
        ))


def create_tree(start, conns, down="|", over="-", sep="-" * 40):
    print("{}\nStarting URL: {}\n\nConnections:".format(sep, start))
    for con in conns:
        print(
            "{}{}{}".format(
                down, over, con
            )
        )
    print(sep)


def get_true_url(url):
    data = url.split("/")
    return "{}//{}".format(data[0], data[2])


def fix_log_file(logfile=get_latest_log_file(CURRENT_LOG_FILE_PATH)):
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
            logger.info(set_color(
                "successfully wrote found items to '{}'...".format(full_file_path)
            ))
        else:
            log.write(data_to_write + "\n")
