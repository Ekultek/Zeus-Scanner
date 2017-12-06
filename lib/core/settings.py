import os
import io
import re
import sys
import glob
import time
import shlex
import difflib
import logging
import base64
import string
import random
import socket
import struct
import platform
import subprocess
try:
    import ConfigParser  # python 2
except ImportError:
    import configparser as ConfigParser  # python 3

import psutil
import requests
import whichcraft

import bin.unzip_gecko
import lib.core.errors
import lib.core.common

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

# issue link
ISSUE_LINK = "https://github.com/ekultek/zeus-scanner/issues"

# current version <major.minor.commit.patch ID>
VERSION = "1.4.2.{}".format(PATCH_ID)

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
SAYING = "Advanced Reconnaissance..."

# i had to create a banner because something not so good happened...
DISCLAIMER = (
    "[!] legal disclaimer: Usage of Zeus for attacking targets without prior mutual consent is illegal. "
    "It is the end user's responsibility to obey all applicable local, state and federal laws. "
    "Developers assume no liability and are not responsible for any misuse or damage caused by this program."
)

# sexy banner
BANNER = """\033[36m
    __          __________                             __   
   / /          \____    /____  __ __  ______          \ \  
  / /    ______   /     // __ \|  |  \/  ___/  ______   \ \ 
  \ \   /_____/  /     /\  ___/|  |  /\___ \  /_____/   / / 
   \_\          /_______ \___  >____//____  >          /_/  
                       \/   \/           \/  {}
\t{}\n\t\t{}\033[0m\n\n\n{}""".format(VERSION_STRING, CLONE, SAYING, DISCLAIMER)

# default user agent if another one isn't given
# reference for best practices: https://docs.developer.amazonservices.com/en_US/dev_guide/DG_UserAgentHeader.html
DEFAULT_USER_AGENT = "Zeus-Scanner/{} (Language=Python/{}; Platform={})".format(
    VERSION, sys.version.split(" ")[0], platform.platform().split("-")[0]
)

# max number of threads allowed
MAX_THREADS = 10

# max amount of pages to search
MAX_PAGE_NUMBER = 500

# path to the checksum
CHECKSUM_PATH = "{}/etc/checksum/md5sum.md5".format(os.getcwd())

# geckodriver version information path, grabs the file that was installed on your system
GECKO_VERSION_INFO_PATH = "{}/bin/version_info".format(os.getcwd())

# path to check if the program has been executed or not
EXECUTED_PATH = "{}/bin/executed.txt".format(os.getcwd())

# paths to sqlmap and nmap
TOOL_PATHS = "{}/bin/paths/path_config.ini".format(os.getcwd())

# attempt to fix the program install error
FIX_PROGRAM_INSTALL_PATH = "{}/etc/scripts/fix_pie.sh".format(os.getcwd())

# path to the auto clean tool
CLEANUP_TOOL_PATH = "{}/etc/scripts/cleanup.sh".format(os.getcwd())

# path to tool to launch sqlmap API
LAUNCH_SQLMAP_API_TOOL = "{}/etc/scripts/launch_sqlmap.sh".format(os.getcwd())

# path to nmap installer
NMAP_INSTALLER_TOOL = "{}/etc/scripts/install_nmap.sh".format(os.getcwd())

# perform a reinstallation of some dependencies
REINSTALL_TOOL = "{}/etc/scripts/reinstall.sh".format(os.getcwd())

# clickjacking HTML test page path
CLICKJACKING_TEST_PAGE_PATH = "{}/etc/html/clickjacking_test_page.html".format(os.getcwd())

# check the site headers to see what it's possibly vulnerable against
HEADER_XML_DATA = "{}/etc/xml/headers.xml".format(os.getcwd())

# holder for sqlmap API ID hashes, makes it so that they are all unique
ALREADY_USED = set()

# holder for protection
PROTECTED = set()

# save the headers to a file for further use
HEADER_RESULT_PATH = "{}/log/header-log".format(os.getcwd())

# path to write the HTML in
CLICKJACKING_RESULTS_PATH = "{}/log/clickjacking-log".format(os.getcwd())

# the log for found admin pages on a site
ADMIN_PAGE_FILE_PATH = "{}/log/admin-page-log".format(os.getcwd())

# path to the sitemap log file
SITEMAP_FILE_LOG_PATH = "{}/log/sitemap-log".format(os.getcwd())

# log path to the whois results
WHOIS_RESULTS_LOG_PATH = "{}/log/whois".format(os.getcwd())

# path to store robot.txt page in
ROBOTS_PAGE_PATH = "{}/log/robots".format(os.getcwd())

# URL's that are extracted from Google's ban URL
EXTRACTED_URL_LOG = "{}/log/extracted-url-log".format(os.getcwd())

# log path for the URL's that are found
URL_LOG_PATH = "{}/log/url-log".format(os.getcwd())

# log path for port scans
PORT_SCAN_LOG_PATH = "{}/log/nmap-scan-log".format(os.getcwd())

# blackwidow log path
SPIDER_LOG_PATH = "{}/log/blackwidow-log".format(os.getcwd())

# cookies log path
COOKIE_LOG_PATH = "{}/log/cookies".format(os.getcwd())

# log to write to for gist searching
GIST_MATCH_LOG = "{}/log/gists".format(os.getcwd())

# unknown firewall log path
UNKNOWN_FIREWALL_FINGERPRINT_PATH = "{}/log/unknown-firewall".format(os.getcwd())

# blacklisted dorks, if your dork doesn't pull any URL's it'll be sent here
BLACKLIST_FILE_PATH = "{}/log/blacklist".format(os.getcwd())

# found PGP keys file path
PGP_KEYS_FILE_PATH = "{}/log/pgp_keys".format(os.getcwd())

# found sqli sites file path
SQLI_SITES_FILEPATH = "{}/log/sqli-sites".format(os.getcwd())

# the current log file being used
CURRENT_LOG_FILE_PATH = "{}/log".format(os.getcwd())

# nmap scan log path
NMAP_LOG_FILE_PATH = "{}/log/nmap-scan-log".format(os.getcwd())

# filename for sitemap log file
SITEMAP_FILENAME = "{}-sitemap.xml"

# filename for robots.txt log file
ROBOTS_TXT_FILENAME = "{}-robots_text.log"

# filename for found admin pages log file
ADMIN_PAGE_FILENAME = "{}-admin-page.log"

# sites found to be possible SQL injection vulnerable
SQLI_FOUND_FILENAME = "sqli-sites.log"

# filename for clickjacking log file
CLICKJACKING_FILENAME = "{}-clickjacking.html"

# filename for gists log file
GIST_FILENAME = "{}-gist-match.log"

# filename for whois lookup log file
WHOIS_LOOKUP_FILENAME = "{}-whois.json"

# filename for unknown firewall log file
UNKNOWN_FIREWALL_FILENAME = "{}-fingerprint.html"

# filename for found cookies log
COOKIE_FILENAME = "{}-cookie.log"

# filename for found headers log
HEADERS_FILENAME = "{}-headers.json"

# filename for extracted IP ban URLs
EXTRACTED_URL_FILENAME = "extracted-url-{}.log"

# filename for the URL log
URL_FILENAME = "url-log-{}.log"

# filename to save the PGP keys
PGP_KEY_FILENAME = "{}-{}.pgp"

# filename for the blacklist log
BLACKLIST_FILENAME = ".blacklist"

# filename for the blackwidow crawler log
BLACKWIDOW_FILENAME = "blackwidow-log-{}.log"

# filename for nmap scans
NMAP_FILENAME = "{}-nmap-scan-results.json"

# github autohorization token path
GITHUB_AUTH_PATH = "{}/etc/auths/git_auth".format(os.getcwd())

# whois authorization token path
WHOIS_AUTH_PATH = "{}/etc/auths/whois_auth".format(os.getcwd())

# nmap's manual page for their options
NMAP_MAN_PAGE_URL = "https://nmap.org/book/man-briefoptions.html"

# sqlmap's manual page for their options
SQLMAP_MAN_PAGE_URL = "https://github.com/sqlmapproject/sqlmap/wiki/Usage"

# whois API link
WHOIS_JSON_LINK = "https://jsonwhoisapi.com/api/v1/whois?identifier={}"

# PGP key identifier to ensure that the link we find is a PGP key
PGP_IDENTIFIER_REGEX = re.compile(r"(0x)?[a-z0-9]{16}", re.I)

# regex to find GET params in a URL, IE php?id=
URL_QUERY_REGEX = re.compile(r"(.*)[?|#](.*){1}\=(.*)")

# regex to recognize a URL
URL_REGEX = re.compile(r"((https?):((//)|(\\\\))+([\w\d:#@%/;$()~_?\+-=\\\.&](#!)?)*)")

# regex to match Google's IP ban URL
IP_BAN_REGEX = re.compile(r"http(s)?.//ipv\d{1}.google.[a-z]{1,5}.", re.I)

# regex to discover if there are any results on the page
NO_RESULTS_REGEX = re.compile("did not match with any results.", re.I)

# WAF/IDS/IPS checking payload
PROTECTION_CHECK_PAYLOAD = (
    "AND 1=1 UNION ALL SELECT 1,NULL,'<script>alert(\"XSS\")</script>',"
    "table_name FROM information_schema.tables WHERE 2>1--/**/; EXEC "
    "xp_cmdshell('cat ../../../etc/passwd')#"
)

# scripts to detect the WAF/IDS/IPS
DETECT_FIREWALL_PATH = "{}/lib/firewall".format(os.getcwd())

# path to run the plugins detection scripts
DETECT_PLUGINS_PATH = "{}/lib/plugins".format(os.getcwd())

# search engines that the application can use
AUTHORIZED_SEARCH_ENGINES = {
    "aol": "http://aol.com",
    "bing": "http://bing.com",
    "duckduckgo": "http://duckduckgo.com/html",
    "google": "http://google.com",
    "search-results": "http://www1.search-results.com/web?tpr={}&q={}&page={}",
    "pgp": "https://pgp.mit.edu/pks/lookup?search={}&op=index"
}

# search page for Gists and rate checking URL
GITHUB_GIST_SEARCH_URLS = {
    "search": "https://api.github.com/gists/public?page={}&per_page=100",
    "check_rate": "https://api.github.com/users/ZeusIssueReporter"

}

# extensions to exclude from the spider
SPIDER_EXT_EXCLUDE = (
    "3ds", "3g2", "3gp", "7z", "DS_Store", "a", "aac", "adp", "ai", "aif", "aiff",
    "apk", "ar", "asf", "au", "avi", "bak", "bin", "bk", "bmp", "btif", "bz2", "cab",
    "caf", "cgm", "cmx", "cpio", "cr2", "dat", "deb", "djvu", "dll", "dmg", "dmp", "dng",
    "doc", "docx", "dot", "dotx", "dra", "dsk", "dts", "dtshd", "dvb", "dwg", "dxf", "ear",
    "ecelp4800", "ecelp7470", "ecelp9600", "egg", "eol", "eot", "epub", "exe", "f4v", "fbs", "fh",
    "fla", "flac", "fli", "flv", "fpx", "fst", "fvt", "g3", "gif", "gz", "h261", "h263", "h264", "ico", "ief",
    "image", "img", "ipa", "iso", "jar", "jpeg", "jpg", "jpgv", "jpm", "jxr", "ktx", "lvp", "lz", "lzma",
    "lzo", "m3u", "m4a", "m4v", "mar", "mdi", "mid", "mj2", "mka", "mkv", "mmr", "mng", "mov", "movie", "mp3",
    "mp4", "mp4a", "mpeg", "mpg", "mpga", "mxu", "nef", "npx", "o", "oga", "ogg", "ogv", "otf", "pbm", "pcx",
    "pdf", "pea", "pgm", "pic", "png", "pnm", "ppm", "pps", "ppt", "pptx", "ps", "psd", "pya", "pyc", "pyo",
    "pyv", "qt", "rar", "ras", "raw", "rgb", "rip", "rlc", "rz", "s3m", "s7z", "scm", "scpt", "sgi", "shar",
    "sil", "smv", "so", "sub", "swf", "tar", "tbz2", "tga", "tgz", "tif", "tiff", "tlz", "ts", "ttf", "uvh",
    "uvi", "uvm", "uvp", "uvs", "uvu", "viv", "vob", "war", "wav", "wax", "wbmp", "wdp", "weba", "webm", "webp",
    "whl", "wm", "wma", "wmv", "wmx", "woff", "woff2", "wvx", "xbm", "xif", "xls", "xlsx", "xlt", "xm", "xpi",
    "xpm", "xwd", "xz", "z", "zip", "zipx", "gov"
)

# urls to exclude from being grabbed during the searching
URL_EXCLUDES = (
    "maps.google", "play.google", "youtube",
    "drive.google", "books.google", "news.google",
    "www.google", "mail.google", "accounts.google",
    "schema.org", "www.<b", "https://cid-", "https://<strong",  # these are some weird things that get pulled up?
    "plus.google", "www.w3.org", "schemas.live.com", "https://my."
    "torproject.org", "search-results.com", "index.com",
    "gov", ".gov", "facebook.com", "instagram.com", "snapchat",
    "stackoverflow", "stackexchange", "github.com", "apple.com",
    "http://my.", "root.cern"
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
def create_log_name(log_path="{}/log", filename="zeus-log-{}.log", matcher="zeus"):
    """
    create the current log file name by figuring out how many files are there
    """
    if not os.path.exists(log_path.format(os.getcwd())):
        os.mkdir(log_path.format(os.getcwd()))
    find_file_amount = len(
        [f for f in os.listdir(log_path.format(os.getcwd())) if matcher in f and not os.path.isdir(f)]
    ) + 1
    full_log_path = "{}/{}".format(log_path.format(os.getcwd()), filename.format(find_file_amount))
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


def parse_conf_file(config_path):
    """
    parse a sqlmap configuration file
    """
    set_options = []
    skip_opt_schema = ("", "False", "0")
    parser = ConfigParser.ConfigParser(allow_no_value=True)
    parser.read(config_path)
    sections = parser.sections()
    for section in sections:
        if not section == "url":
            for opt in parser.options(section):
                if not any(schema == str(parser.get(section, opt)) for schema in skip_opt_schema):
                    set_options.append((str(opt), str(parser.get(section, opt))))
    return set_options


def set_color(org_string, level=None):
    """
    set the console log color, this will kinda mess with the file log but whatever
    """
    color_levels = {
        10: "\033[36m{}\033[0m",         # DEBUG
        15: "\033[1m\033[36m{}\033[0m",  # GOOD DEBUG INFO
        20: "\033[32m{}\033[0m",         # INFO *default
        25: "\033[1m\033[32m{}\033[0m",  # GOOD INFO
        30: "\033[33m{}\033[0m",         # WARNING
        35: "\033[1m\033[33m{}\033[0m",  # DEPRECATION
        40: "\033[31m{}\033[0m",         # ERROR
        50: "\033[7;31;31m{}\033[0m"     # FATAL/CRITICAL/EXCEPTION
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


def grab_random_agent(agent_path="{}/etc/text_files/agents.txt", verbose=False):
    """
    grab a random user agent from the agent file
    """
    if verbose:
        logger.debug(set_color(
            "grabbing random user-agent from '{}'...".format(agent_path.format(os.getcwd())), level=10
        ))
    with open(agent_path.format(os.getcwd())) as agents:
        retval = random.choice(agents.readlines())
    logger.info(set_color(
        "random agent being used '{}'...".format(retval.strip())
    ))
    return retval.strip()


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


def get_random_dork(filename="{}/etc/text_files/dorks.txt"):
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
    open(logfile, "w").close()  # completely erase the log file
    with open(logfile, "a+") as fixed:
        for line in retval.split("\n"):
            fixed.write(line + "\n")  # rewrite everything back to normal


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
    elif enum is not None:
        logger.info(set_color(
            "running enumeration on given file '{}'...".format(enum)
        ))
        se = None
    else:
        if verbose:
            logger.debug(set_color(
                "using default search engine (Google)...", level=10
            ))
        logger.info(set_color(
            "using default search engine..."
        ))
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
    conf_file = kwargs.get("conf", None)

    logger.info(set_color(
        "creating arguments for {}...".format("sqlmap" if sqlmap else "nmap")
    ))
    retval = []
    splitter = {"sqlmap": ",", "nmap": "|"}
    if conf_file is not None:
        set_options = parse_conf_file(conf_file)
        for opt in set_options:
            for o in SQLMAP_API_OPTIONS:
                if not opt[0] == "url":
                    if o.lower() == opt[0]:
                        retval.append((o, opt[1]))
    elif sqlmap:
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


def create_random_ip():
    """
    create a random IP address, no testing if it is valid or not
    """

    def __get_nodes():
        return str(socket.inet_ntoa(struct.pack(">I", random.randint(1, 0xffffffff))))

    generated = __get_nodes()
    if generated == "0.0.0.0" or "255.255.255.255":
        generated = __get_nodes()  # if it isn't a real IP regenerate it
    logger.info(set_color(
        "random IP address generated for header '{}'...".format(generated)
    ))
    return generated


def rewrite_all_paths():
    """
    rewrite all the paths in case we hit a certain error, this will force a reinstall of the
    geckodriver
    """
    gecko_path = whichcraft.which("geckodriver")
    os.remove(gecko_path)
    paths = (TOOL_PATHS, GECKO_VERSION_INFO_PATH)
    for path in paths:
        open(path, "w").close()
    with open(EXECUTED_PATH, "w") as log:
        log.write("FALSE")


def check_for_protection(protected, attack_type):
    """
    check if the provided target URL has header protection against an attack type
    """
    if protected is not None:
        items = [item.lower() for item in protected]

        if attack_type in items or "all" in items:
            logger.warning(set_color(
                "provided target seems to have protection against this attack type...", level=30
            ))
            protected.clear()  # clear the set
        return True


def deprecation(target_version, method, connect=True, *args, **kwargs):
    """
    show a deprecation warning and return the function with the correct given arguments
    """
    if connect:
        print(
            "[{} DEPRECATION] {}".format(
                time.strftime("%H:%M:%S"), set_color(
                    "{} will be deprecated by version {}...".format(
                        method.__name__, target_version
                    ), level=35
                )
            )
        )
        return method(args, kwargs)
    else:
        print(
            "[{} DEPRECATION] {}".format(
                time.strftime("%H:%M:%S"), set_color(
                    "{} has been deprecated and will no longer work, "
                    "this attack type will be completely removed by v{}...".format(
                        method.__name__, target_version
                    ), level=35
                )
            )
        )
        lib.core.common.shutdown()


def check_thread_num(number, batch=False, default=5):
    """
    if you specify more threads then the max number you will be prompted if not running batch
    """
    logger.warning(set_color(
        "you have specified {} threads, it is highly advised to not go over {} threads, "
        "doing so will most likely not give a significant performance increase and also "
        "will most likely cause unforeseen issues...".format(number, MAX_THREADS), level=30
    ))
    question_msg = "would you like to continue anyways"
    default_msg = "defaulting to 5 threads..."
    if not batch:
        question = lib.core.common.prompt(
            question_msg, opts="yN"
        )
        if question.lower().startswith("n"):
            logger.info(set_color(
                default_msg
            ))
            return default
    else:
        lib.core.common.prompt(
            question_msg, opts="yN", default="n"
        )
        logger.info(set_color(
            default_msg
        ))
        return default
    return number


def run_attacks(url, **kwargs):
    """
    run the attacks if any are requested
    """
    nmap = kwargs.get("nmap", False)
    sqlmap = kwargs.get("sqlmap", False)
    xss = kwargs.get("xss", False)
    admin = kwargs.get("admin", False)
    verbose = kwargs.get("verbose", False)
    whois = kwargs.get("whois", False)
    clickjacking = kwargs.get("clickjacking", False)
    github = kwargs.get("github", False)
    pgp = kwargs.get("pgp", False)
    auto_start = kwargs.get("auto_start", False)
    sqlmap_arguments = kwargs.get("sqlmap_args", None)
    nmap_arguments = kwargs.get("nmap_args", None)
    show_all = kwargs.get("show_all", False)
    do_threading = kwargs.get("do_threading", False)
    batch = kwargs.get("batch", False)
    tamper_script = kwargs.get("tamper_script", None)
    timeout = kwargs.get("timeout", None)
    forwarded = kwargs.get("xforward", None)
    proxy = kwargs.get("proxy", None)
    agent = kwargs.get("agent", None)
    conf_file = kwargs.get("conf_file", None)
    threads = kwargs.get("threads", None)

    if threads > MAX_THREADS:
        threads = check_thread_num(threads, batch=batch)

    __enabled_attacks = {
        "sqlmap": sqlmap,
        "port": nmap,
        "xss": xss,
        "admin": admin,
        "whois": whois,
        "clickjacking": clickjacking
    }

    enabled = set()
    for key in __enabled_attacks.keys():
        if __enabled_attacks[key] is True:
            enabled.add(key)
        if len(enabled) > 1:
            logger.error(set_color(
                "it appears that you have enabled multiple attack types, "
                "as of now only 1 attack is supported at a time, choose "
                "your attack and try again. You can use the -f flag if "
                "you do not want to complete an entire search again "
                "(IE -f /home/me/zeus-scanner/log/url-log/url-log-1.log)...", level=40
            ))
            lib.core.common.shutdown()

    question_msg = "would you like to process found URL: '{}'".format(url)
    if not batch:
        question = lib.core.common.prompt(
            question_msg, opts="yN"
        )
    else:
        question = lib.core.common.prompt(
            question_msg, opts="yN", default="y"
        )

    if question.lower().startswith("y"):
        if sqlmap:
            from lib.attacks import sqlmap_scan
            return sqlmap_scan.sqlmap_scan_main(
                url.strip(), verbose=verbose,
                opts=create_arguments(sqlmap=True, sqlmap_args=sqlmap_arguments, conf=conf_file), auto_start=auto_start)
        elif nmap:
            from lib.attacks import nmap_scan
            url_ip_address = replace_http(url.strip())
            return nmap_scan.perform_port_scan(
                url_ip_address, verbose=verbose, timeout=timeout,
                opts=create_arguments(nmap=True, nmap_args=nmap_arguments)
            )
        elif admin:
            from lib.attacks.admin_panel_finder import main
            main(
                url, show=show_all, proc_num=threads,
                verbose=verbose, do_threading=do_threading, batch=batch
            )
        elif xss:
            from lib.attacks.xss_scan import main_xss
            if check_for_protection(PROTECTED, "xss"):
                main_xss(
                    url, verbose=verbose, proxy=proxy,
                    agent=agent, tamper=tamper_script, batch=batch,
                )
        elif whois:
            from lib.attacks.whois_lookup.whois import whois_lookup_main
            whois_lookup_main(
                url, verbose=verbose, timeout=timeout
            )
        elif clickjacking:
            from lib.attacks.clickjacking_scan import clickjacking_main
            if check_for_protection(PROTECTED, "clickjacking"):
                clickjacking_main(url, agent=agent, proxy=proxy,
                                  forward=forwarded, batch=batch)
        elif github:
            from lib.attacks.gist_lookup import github_gist_search_main
            query = replace_http(url)
            github_gist_search_main(query, agent=agent, proxy=proxy, verbose=verbose)
        elif pgp:
            from var.search.pgp_search import pgp_main
            pgp_main(url, verbose=verbose)
        else:
            pass
    else:
        logger.warning(set_color(
            "skipping '{}'...".format(url), level=30
        ))


def parse_blacklist(dork, path, batch=False):
    """
    parse the built-in blacklist to see if your dork is already in there or not
    """
    create_dir(path)
    dork = dork.strip()
    full_path = "{}/.blacklist".format(path)
    prompt_msg = (
        "it appears your query '{}' is blacklisted (no usable sites found with it) "
        "continuing will most likely result in finding no URL's, would you like to "
        "continue anyways".format(dork)
    )
    with open(full_path, "a+") as log:
        dorks = log.readlines()
        if any(d.strip() == dork for d in dorks):
            if not batch:
                question = lib.core.common.prompt(
                    prompt_msg, opts="yN"
                )
                if not question.lower().startswith("y"):
                    lib.core.common.shutdown()
            else:
                lib.core.common.prompt(prompt_msg, opts="yN", default="n")
    return True


def calculate_success(amount_of_urls):
    """
    calculate the success rate of the found links
    """
    success_percentage = ((amount_of_urls // 10) + 1) * 10
    if success_percentage < 25:
        success_rate = "low"
    elif 25 < success_percentage < 50:
        success_rate = "fair"
    elif 50 < success_percentage < 75:
        success_rate = "good"
    elif 75 <= success_percentage <= 110:
        success_rate = "great"
    else:
        success_rate = "outstanding"
    return success_rate


def __get_encoded_string(path):
    """
    get the encoded authorization string
    """
    with open(path.format(os.getcwd())) as log:
        return log.read()


def __get_n(encoded):
    """
    get the n'th number for decoding
    """
    return encoded.split(":")[-1]


def __decode(encoded, n):
    """
    decode the string
    """
    token = encoded.split(":")[0]
    for _ in range(0, n):
        token = base64.b64decode(token)
    return token


def get_token(path):
    """
    get the authorization token
    """
    encoded = __get_encoded_string(path)
    n = __get_n(encoded)
    token = __decode(encoded, int(n))
    return token


def tails(file_object, last_lines=50):
    """
    return the last `n` lines of a file, much like the Unix
    tails command
    """
    with open(file_object) as file_object:
        assert last_lines >= 0
        pos, lines = last_lines+1, []
        while len(lines) <= last_lines:
            try:
                file_object.seek(-pos, 2)
            except IOError:
                file_object.seek(0)
                break
            finally:
                lines = list(file_object)
            pos *= 2
    return "".join(lines[-last_lines:])


def convert_to_minutes(seconds):
    """
    convert an amount of seconds to minutes and seconds
    """
    import time
    return time.strftime("%M:%S", time.gmtime(seconds))
