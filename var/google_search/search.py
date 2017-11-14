import os
import re
import time
import shlex
import subprocess

try:
    from urllib import (  # python 2
        unquote
    )
except ImportError:
    from urllib.parse import (  # python 3
        unquote
    )

import requests
import whichcraft
from bs4 import BeautifulSoup
from selenium import webdriver
from pyvirtualdisplay import Display
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.proxy import *
from selenium.webdriver.remote.errorhandler import (
    UnexpectedAlertPresentException,
    ElementNotInteractableException
)

from var.auto_issue.github import request_issue_creation
from lib.core.settings import (
    logger,
    set_color,
    proxy_string_to_dict,
    DEFAULT_USER_AGENT,
    URL_QUERY_REGEX,
    URL_REGEX,
    shutdown,
    URL_LOG_PATH,
    write_to_log_file,
    prompt,
    EXTRACTED_URL_LOG,
    URL_EXCLUDES,
    CLEANUP_TOOL_PATH,
    FIX_PROGRAM_INSTALL_PATH,
    create_random_ip,
    rewrite_all_paths,
    AUTHORIZED_SEARCH_ENGINES,
    MAX_PAGE_NUMBER,
    NO_RESULTS_REGEX,
    parse_blacklist,
    BLACKLIST_FILE_PATH
)

try:
    unicode
except NameError:
    unicode = str


def strip_leftovers(url, possibles):
    """
    strip leftover HTML tags and random garbage data that is sometimes found in the URL's
    """
    for p in possibles:
        if p in url:
            url = url.split(p)[0]
    return url


def extract_ip_ban(url):
    """
    bypass Google's IP blocking by extracting the true URL from the ban URL.
    """
    url = unquote(url)
    constant_splitter = "continue="
    content_separators = ("Fid", "&gs_")
    to_use_separator = None
    retval = None
    url_data_list = url.split(constant_splitter)
    for item in url_data_list:
        for sep in content_separators:
            if sep in item:
                to_use_separator = sep
        retval = item.split(to_use_separator)[0]
    return unquote(retval)


def set_tor_browser_settings(ff_browser, default_port="9050", **kwargs):
    """
    set the Firefox browser settings to mimic the Tor browser
    """
    port = kwargs.get("port", None)
    verbose = kwargs.get("verbose", False)
    user_agent = kwargs.get("agent", None)
    if port is not None:
        port = port
    else:
        port = default_port
    if verbose:
        logger.debug(set_color(
            "tor port set to '{}'...".format(port), level=10
        ))
    preferences = {
        "privacy": [
            # set the privacy settings
            ("places.history.enabled", False),
            ("privacy.clearOnShutdown.offlineApps", True),
            ("privacy.clearOnShutdown.passwords", True),
            ("privacy.clearOnShutdown.siteSettings", True),
            ("privacy.sanitize.sanitizeOnShutdown", True),
            ("signon.rememberSignons", False),
            ("network.cookie.lifetimePolicy", 2),
            ("network.dns.disablePrefetch", True),
            ("network.http.sendRefererHeader", 0)
        ],
        "proxy": [
            # set the proxy settings
            ("network.proxy.type", 1),
            ("network.proxy.socks_version", 5),
            ("network.proxy.socks", '127.0.0.1'),
            ("network.proxy.socks_port", int(port)),
            ("network.proxy.socks_remote_dns", True)
        ],
        "javascript": [
            # disabled the javascript settings
            ("javascript.enabled", False)
        ],
        "download": [
            # get a speed increase by not downloading the images
            ("permissions.default.image", 2)
        ],
        "user-agent": [
            # set the user agent settings
            ("general.useragent.override", user_agent)
        ]
    }
    for preference in preferences.iterkeys():
        if verbose:
            logger.debug(set_color(
                "setting '{}' preference(s)...".format(preference), level=10
            ))
        for setting in preferences[preference]:
            ff_browser.set_preference(setting[0], setting[1])
    return ff_browser


def extract_webcache_url(webcache_url, splitter="+"):
    """
    extract the true URL from Google's webcache URL's
    """
    webcache_url = unquote(webcache_url)
    webcache_regex = re.compile(r"cache:(.{,16})?:")
    data = webcache_regex.split(webcache_url)
    to_extract = data[2].split(splitter)
    extracted_to_test = to_extract[0]
    if URL_REGEX.match(extracted_to_test):
        return extracted_to_test
    return None


def get_urls(query, url, verbose=False, warning=True, **kwargs):
    """
      Bypass Google captchas and Google API by using selenium-webdriver to gather
      the Google URL. This will open a robot controlled browser window and attempt
      to get a URL from Google that will be used for scraping afterwards.
    """
    query = query.decode('unicode_escape').encode('utf-8')
    proxy, user_agent = kwargs.get("proxy", None), kwargs.get("user_agent", None)
    tor, tor_port = kwargs.get("tor", False), kwargs.get("tor_port", None)
    batch = kwargs.get("batch", False)
    if verbose:
        logger.debug(set_color(
            "setting up the virtual display to hide the browser...", level=10
        ))
    if tor:
        if "google" in url:
            logger.warning(set_color(
                "using Google with tor will most likely result in a ban URL...", level=30
            ))
    ff_display = Display(visible=0, size=(800, 600))
    ff_display.start()
    logger.info(set_color(
        "firefox browser display will be hidden while it performs the query..."
    ))
    if warning:
        logger.warning(set_color(
            "your web browser will be automated in order for Zeus to successfully "
            "bypass captchas and API calls. this is done in order to grab the URL "
            "from the search and parse the results. please give selenium time to "
            "finish it's task...", level=30
        ))
    if verbose:
        logger.debug(set_color(
            "running selenium-webdriver and launching browser...", level=10
        ))

    if verbose:
        logger.debug(set_color(
            "adjusting selenium-webdriver user-agent to '{}'...".format(user_agent), level=10
        ))
    if not tor and proxy is not None:
        proxy_type = proxy.keys()
        proxy_to_use = Proxy({
            "proxyType": ProxyType.MANUAL,
            "httpProxy": proxy[proxy_type[0]],
            "ftpProxy": proxy[proxy_type[0]],
            "sslProxy": proxy[proxy_type[0]],
            "noProxy": ""
        })
        if verbose:
            logger.debug(set_color(
                "setting selenium proxy to '{}'...".format(
                    ''.join(proxy_type) + "://" + ''.join(proxy.values())
                ), level=10
            ))
    else:
        proxy_to_use = None

    try:
        profile = webdriver.FirefoxProfile()
        if not tor:
            profile.set_preference("general.useragent.override", user_agent)
            browser = webdriver.Firefox(profile, proxy=proxy_to_use)
        else:
            logger.info(set_color(
                "setting tor browser settings..."
            ))
            profile = set_tor_browser_settings(profile, verbose=verbose, agent=user_agent, port=tor_port)
            browser = webdriver.Firefox(profile)
    except OSError:
        if not tor:
            profile.set_preference("general.useragent.override", user_agent)
            browser = webdriver.Firefox(profile, proxy=proxy_to_use, executable_path=whichcraft.which("geckodriver"))
        else:
            profile = set_tor_browser_settings(profile, verbose=verbose, agent=user_agent, port=tor_port)
            browser = webdriver.Firefox(profile, executable_path=whichcraft.which("geckodriver"))

    logger.info(set_color("browser will open shortly..."))
    browser.get(url)
    if verbose:
        logger.debug(set_color(
            "searching search engine for the 'q' element (search button)...", level=10
        ))
    search = browser.find_element_by_name('q')
    logger.info(set_color(
        "searching search engine using query '{}'...".format(url, query)
    ))
    try:
        search.send_keys(query)
        search.send_keys(Keys.RETURN)  # hit return after you enter search text
        if not tor:
            time.sleep(3)
        else:
            logger.warning(set_color(
                "sleep time has been increased to 10 seconds due to tor being used...", level=30
            ))
            time.sleep(10)
    except ElementNotInteractableException:
        browser.execute_script("document.querySelectorAll('label.boxed')[1].click()")
        search.send_keys(query)
        search.send_keys(Keys.RETURN)  # hit return after you enter search text
        time.sleep(3)
    except UnicodeDecodeError:
        logger.error(set_color(
            "your query '{}' appears to have unicode characters in it, selenium is not "
            "properly formatted to handle unicode characters, this dork will be skipped...".format(
                query
            ), level=40
        ))
    if verbose:
        logger.debug(set_color(
            "obtaining URL from selenium..."
        ))
    try:
        retval = browser.current_url
    except UnexpectedAlertPresentException:
        logger.warning(set_color(
            "alert present, closing...", level=30
        ))
        alert = browser.switch_to.alert
        alert.accept()
        retval = browser.current_url
    ban_url_schema = ["http://ipv6.google.com", "http://ipv4.google.com"]
    if any(u in retval for u in ban_url_schema):  # if you got IP banned
        logger.warning(set_color(
            "it appears that Google is attempting to block your IP address, attempting bypass...", level=30
        ))
        try:
            retval = extract_ip_ban(retval)
            question_msg = (
                "zeus was able to successfully extract the URL from Google's ban URL "
                "it is advised to shutdown zeus and attempt to extract the URL's manually. "
                "failing to do so will most likely result in no results being found by zeus. "
                "would you like to shutdown"
            )
            if not batch:
                do_continue = prompt(
                    question_msg, opts="yN"
                )
            else:
                do_continue = prompt(
                    question_msg, opts="yN", default="n"
                )

            if not str(do_continue).lower().startswith("n"):  # shutdown and write the URL to a file
                write_to_log_file(retval, EXTRACTED_URL_LOG, "extracted-url-{}.log")
                logger.info(set_color(
                    "it is advised to extract the URL's from the produced URL written to the above "
                    "(IE open the log, copy the url into firefox)...".format(retval)
                ))
                shutdown()
        except Exception as e:
            browser.close()  # stop all the random rogue processes
            ff_display.stop()
            logger.exception(set_color(
                "zeus was unable to extract the correct URL from the ban URL '{}', "
                "got exception '{}'...".format(
                    unquote(retval), e
                ), level=50
            ))
            request_issue_creation()
            shutdown()
    if verbose:
        logger.debug(set_color(
            "found current URL from selenium browser...", level=10
        ))
    logger.info(set_color(
        "closing the browser and continuing process.."
    ))
    browser.close()
    ff_display.stop()
    return retval


def parse_search_results(query, url_to_search, verbose=False, **kwargs):
    """
      Parse a webpage from Google for URL's with a GET(query) parameter
    """
    possible_leftovers = ("<", ">", ";", ",")
    splitter = "&amp;"
    retval = set()
    query_url = None

    parse_webcache, pull_all = kwargs.get("parse_webcache", False), kwargs.get("pull_all", False)
    proxy_string, user_agent = kwargs.get("proxy", None), kwargs.get("agent", None)
    forward_for = kwargs.get("forward_for", False)
    tor = kwargs.get("tor", False)
    batch = kwargs.get("batch", False)

    if verbose:
        logger.debug(set_color(
            "parsing blacklist...", level=10
        ))
    parse_blacklist(query, BLACKLIST_FILE_PATH, batch=batch)

    if verbose:
        logger.debug(set_color(
            "checking for user-agent and proxy configuration...", level=10
        ))

    if not parse_webcache:
        logger.warning(set_color(
            "will not parse webcache URL's (to parse webcache pass -W)...", level=30
        ))
    if not pull_all:
        logger.warning(set_color(
            "only pulling URLs with GET(query) parameters (to pull all URL's pass -E)...", level=30
        ))

    user_agent_info = "adjusting user-agent header to {}..."
    if user_agent is not DEFAULT_USER_AGENT:
        user_agent_info = user_agent_info.format(user_agent.strip())
    else:
        user_agent_info = user_agent_info.format("default user agent '{}'".format(DEFAULT_USER_AGENT))

    proxy_string_info = "setting proxy to {}..."
    if proxy_string is not None:
        proxy_string = proxy_string_to_dict(proxy_string)
        proxy_string_info = proxy_string_info.format(
            ''.join(proxy_string.keys()) + "://" + ''.join(proxy_string.values()))
    elif tor:
        proxy_string = proxy_string_to_dict("socks5://127.0.0.1:9050")
        proxy_string_info = proxy_string_info.format(
            "tor proxy settings"
        )
    else:
        proxy_string_info = "no proxy configuration detected..."

    if forward_for:
        ip_to_use = (create_random_ip(), create_random_ip(), create_random_ip())
        if verbose:
            logger.debug(set_color(
                "random IP addresses generated for headers '{}'...".format(ip_to_use), level=10
            ))

        headers = {
            "Connection": "close",
            "user-agent": user_agent,
            "X-Forwarded-For": "{}, {}, {}".format(ip_to_use[0], ip_to_use[1], ip_to_use[2])
        }
    else:
        headers = {
            "Connection": "close",
            "user-agent": user_agent
        }
    logger.info(set_color(
        "attempting to gather query URL..."
    ))
    try:
        query_url = get_urls(
            query, url_to_search, verbose=verbose, user_agent=user_agent, proxy=proxy_string,
            tor=tor, batch=batch
        )
    except Exception as e:
        if "'/usr/lib/firefoxdriver/webdriver.xpi'" in str(e):
            logger.fatal(set_color(
                "firefox was not found in the default location on your system, "
                "check your installation and make sure it is in /usr/lib, if you "
                "find it there, restart your system and try again...", level=50
            ))
        elif "connection refused" in str(e):
            logger.fatal(set_color(
                "there are to many sessions of firefox opened and selenium cannot "
                "create a new one...", level=50
            ))
            do_autoclean = prompt(
                "would you like to attempt to auto clean the open sessions", opts="yN"
            )
            if do_autoclean.lower().startswith("y"):
                logger.warning(set_color(
                    "this will kill all instances of the firefox web browser...", level=30
                ))
                auto_clean_command = shlex.split("sudo sh {}".format(CLEANUP_TOOL_PATH))
                subprocess.call(auto_clean_command)
                logger.info(set_color(
                    "all open sessions of firefox killed, it should be safe to re-run "
                    "Zeus..."
                ))
            else:
                logger.warning(set_color(
                    "kill off the open sessions of firefox and re-run Zeus...", level=30
                ))
            shutdown()
        elif "Program install error!" in str(e):
            do_fix = prompt(
                "seems the program is having some trouble installing would you like "
                "to try and automatically fix this issue", opts="yN"
            )
            if do_fix.lower().startswith("y"):
                logger.info(set_color(
                    "attempting to reinstall failing dependency..."
                ))
                do_fix_command = shlex.split("sudo sh {}".format(FIX_PROGRAM_INSTALL_PATH))
                subprocess.call(do_fix_command)
                logger.info(set_color(
                    "successfully installed, you should be good to re-run Zeus..."
                ))
                shutdown()
            else:
                logger.info(set_color(
                    "you can automatically try and re-install Xvfb to fix the problem..."
                ))
                shutdown()
        elif "Message: Reached error page:" in str(e):
            logger.fatal(set_color(
                "geckodriver has hit an error that usually means it needs to be reinstalled...", level=50
            ))
            question = prompt(
                "would you like to attempt a reinstallation of the geckodriver", opts="yN"
            )
            if question.lower().startswith("y"):
                logger.warning(set_color(
                    "rewriting all executed information, path information, and removing geckodriver...", level=30
                ))
                rewrite_all_paths()
                logger.info(set_color(
                    "all paths rewritten, you will be forced to re-install everything next run of Zeus..."
                ))
            else:
                logger.fatal(set_color(
                    "you will need to remove the geckodriver from /usr/bin and reinstall it...", level=50
                ))
                shutdown()
        else:
            logger.exception(set_color(
                "{} failed to gather the URL from search engine, caught exception '{}' "
                "exception has been logged to current log file...".format(
                    os.path.basename(__file__), str(e).strip()), level=50)
            )
            request_issue_creation()
        shutdown()
    logger.info(set_color(
        "URL successfully gathered, searching for GET parameters..."
    ))

    logger.info(set_color(proxy_string_info))
    req = requests.get(query_url, proxies=proxy_string, params=headers)
    logger.info(set_color(user_agent_info))
    req.headers.update(headers)
    found_urls = URL_REGEX.findall(req.text)
    for urls in list(found_urls):
        for url in list(urls):
            url = unquote(url)
            if not any(u in url for u in URL_EXCLUDES):
                if not url == "http://" and not url == "https://":
                    if URL_REGEX.match(url):
                        if isinstance(url, unicode):
                            url = str(url).encode("utf-8")
                        if pull_all:
                            retval.add(url.split(splitter)[0])
                        else:
                            if URL_QUERY_REGEX.match(url.split(splitter)[0]):
                                retval.add(url.split(splitter)[0])
                        if verbose:
                            try:
                                logger.debug(set_color(
                                    "found '{}'...".format(url.split(splitter)[0]), level=10
                                ))
                            except TypeError:
                                logger.debug(set_color(
                                    "found '{}'...".format(str(url).split(splitter)[0]), level=10
                                ))
                            except AttributeError:
                                logger.debug(set_color(
                                    "found '{}...".format(str(url)), level=10
                                ))
                        if url is not None:
                            retval.add(url.split(splitter)[0])
    true_retval = set()
    for url in list(retval):
        if any(l in url for l in possible_leftovers):
            url = strip_leftovers(url, list(possible_leftovers))
        if parse_webcache:
            if "webcache" in url:
                logger.info(set_color(
                    "found a webcache URL, extracting..."
                ))
                url = extract_webcache_url(url)
                if verbose:
                    logger.debug(set_color(
                        "found '{}'...".format(url), level=10
                    ))
                true_retval.add(url)
            else:
                true_retval.add(url)
        else:
            true_retval.add(url)

    if len(true_retval) != 0:
        write_to_log_file(true_retval, URL_LOG_PATH, "url-log-{}.log")
    else:
        logger.fatal(set_color(
            "did not find any URLs with given query '{}' writing query to blacklist...".format(query), level=50
        ))
        write_to_log_file(query, BLACKLIST_FILE_PATH, ".blacklist", blacklist=True)
        shutdown()
    logger.info(set_color(
        "found a total of {} URLs with given query '{}'...".format(len(true_retval), query)
    ))
    return list(true_retval) if len(true_retval) != 0 else None


def search_multiple_pages(query, link_amount, verbose=False, **kwargs):
    """
    search multiple pages for a lot of links, this will not be done via Google
    """
    proxy = kwargs.get("proxy", None)
    agent = kwargs.get("agent", None)
    xforward = kwargs.get("xforward", False)
    attrib, desc = "a", "href"
    retval = set()
    search_engine = AUTHORIZED_SEARCH_ENGINES["search-results"]

    logger.warning(set_color(
        "searching multiple pages will not be done on Google...".format(search_engine), level=30
    ))

    if not xforward:
        params = {
            "Connection": "close",
            "user-agent": agent
        }
    else:
        ip_list = (create_random_ip(), create_random_ip(), create_random_ip())
        params = {
            "Connection": "close",
            "user-agent": agent,
            "X-Forwarded-For": "{}, {}, {}".format(ip_list[0], ip_list[1], ip_list[2])
        }

    page_number = 1
    try:
        while len(retval) <= link_amount:
            if verbose:
                logger.debug(set_color(
                    "searching page number {}...".format(page_number), level=10
                ))
            if page_number % 10 == 0:
                logger.info(set_color(
                    "currently on page {} of search results...".format(
                        page_number
                    )
            ))
            page_request = requests.get(
                search_engine.format(page_number, query, page_number), params=params,
                proxies=proxy_string_to_dict(proxy)
            )
            if page_request.status_code == 200:
                html_page = page_request.content
                soup = BeautifulSoup(html_page, "html.parser")
                if not NO_RESULTS_REGEX.findall(str(soup)):
                    for link in soup.findAll(attrib):
                        redirect = link.get(desc)
                        if redirect is not None:
                            if not any(ex in redirect for ex in URL_EXCLUDES):
                                if URL_REGEX.match(redirect):
                                    retval.add(redirect)
                    if page_number < MAX_PAGE_NUMBER:
                        page_number += 1
                    else:
                        logger.warning(set_color(
                            "hit max page number {}...".format(MAX_PAGE_NUMBER), level=30
                        ))
                        break
                else:
                    logger.warning(set_color(
                        "no more results found for given query '{}'...".format(query), level=30
                    ))
                    break
    except KeyboardInterrupt:
        logger.error(set_color(
            "user aborted, dumping already found URL(s)...", level=40
        ))
        write_to_log_file(retval, URL_LOG_PATH, "url-log-{}.log")
        logger.info(set_color(
            "found a total of {} URL(s)...".format(len(retval)), level=25
        ))
        shutdown()
    except Exception as e:
        logger.exception(set_color(
            "Zeus ran into an unexpected error '{}'...".format(e), level=50
        ))
        request_issue_creation()
        shutdown()

    logger.info(set_color(
        "a total of {} URL(s) found out of the requested {}...".format(len(retval), link_amount), level=25
    ))
    write_to_log_file(retval, URL_LOG_PATH, "url-log-{}.log")
    return list(retval) if len(retval) != 0 else None
