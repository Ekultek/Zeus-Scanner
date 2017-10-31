import os
import re
import time
import shlex
import subprocess

try:
    from urllib import (
        unquote,
    )
except ImportError:
    from urllib.parse import (
        unquote,
    )

import requests
import httplib2
import google as google_api
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
    get_proxy_type,
    prompt,
    EXTRACTED_URL_LOG,
    URL_EXCLUDES,
    CLEANUP_TOOL_PATH,
    FIX_PROGRAM_INSTALL_PATH,
    create_random_ip
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


def bypass_ip_block(url):
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
    if verbose:
        logger.debug(set_color(
            "setting up the virtual display to hide the browser...", level=10
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
    if proxy is not None:
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

    profile = webdriver.FirefoxProfile()
    profile.set_preference("general.useragent.override", user_agent)
    browser = webdriver.Firefox(profile, proxy=proxy_to_use)
    logger.info(set_color("browser will open shortly..."))
    browser.get(url)
    if verbose:
        logger.debug(set_color(
            "searching search engine for the 'q' element (search button)...", level=10
        ))
    search = browser.find_element_by_name('q')
    logger.info(set_color(
        "searching '{}' using query '{}'...".format(url, query)
    ))
    try:
        search.send_keys(query)
        search.send_keys(Keys.RETURN)  # hit return after you enter search text
        time.sleep(3)
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
            retval = bypass_ip_block(retval)
            do_continue = prompt(
                "zeus was able to successfully extract the URL from Google's ban URL "
                "it is advised to shutdown zeus and attempt to extract the URL's manually. "
                "failing to do so will most likely result in no results being found by zeus. "
                "would you like to shutdown", opts="yN"
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
    else:
        proxy_string_info = "no proxy configuration detected..."

    if forward_for:
        ip_to_use = (create_random_ip(), create_random_ip(), create_random_ip())
        if verbose:
            logger.debug(set_color(
                "random IP address generated for headers '{}'...".format(ip_to_use), level=10
            ))

        headers = {
            "Connection": "close",
            "user-agent": user_agent,
            "X-Forward-For": "{}, {}, {}".format(ip_to_use[0], ip_to_use[1], ip_to_use[2])
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
        query_url = get_urls(query, url_to_search, verbose=verbose, user_agent=user_agent, proxy=proxy_string)
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
    req = requests.get(query_url, proxies=proxy_string)
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
            "did not find any URLs with given query '{}'...".format(query), level=50
        ))
        shutdown()
    logger.info(set_color(
        "found a total of {} URLs with given query '{}'...".format(len(true_retval), query)
    ))
    return list(true_retval) if len(true_retval) != 0 else None


def search_multiple_pages(query, link_amount, verbose=False, **kwargs):
    def __config_proxy(proxy_string):
        proxy_type_schema = {
            "http": httplib2.socks.PROXY_TYPE_HTTP,
            "socks4": httplib2.socks.PROXY_TYPE_SOCKS4,
            "socks5": httplib2.socks.PROXY_TYPE_SOCKS5
        }
        proxy_type = get_proxy_type(proxy_string)[0]
        proxy_dict = proxy_string_to_dict(proxy_string)
        proxy_config = httplib2.ProxyInfo(
            proxy_type=proxy_type_schema[proxy_type],
            proxy_host="".join(proxy_dict.keys()),
            proxy_port="".join(proxy_dict.values())
        )
        return proxy_config

    proxy, agent = kwargs.get("proxy", None), kwargs.get("agent", None)

    if proxy is not None:
        if verbose:
            logger.debug(set_color(
                "configuring to use proxy '{}'...".format(proxy), level=10
            ))
        __config_proxy(proxy)

    if agent is not None:
        if verbose:
            logger.debug(set_color(
                "settings user-agent to '{}'...".format(agent), level=10
            ))

    logger.warning(set_color(
        "multiple pages will be searched using Google's API client, searches may be blocked after a certain "
        "amount of time...", level=30
    ))
    results, limit, found, index = set(), link_amount, 0, google_api.search(query, user_agent=agent, safe="on")
    try:
        while limit > 0:
            results.add(next(index))
            limit -= 1
            found += 1
    except Exception as e:
        if "Error 503" in str(e):
            logger.fatal(set_color(
                "Google is blocking the current IP address, dumping already found URL's...", level=50
            ))
            results = results
            pass

    retval = set()
    for url in results:
        if URL_REGEX.match(url) and URL_QUERY_REGEX.match(url):
            if verbose:
                logger.debug(set_color(
                    "found '{}'...".format(url), level=10
                ))
            retval.add(url)

    if len(retval) != 0:
        logger.info(set_color(
            "a total of {} links found out of requested {}...".format(
                len(retval), link_amount
            )
        ))
        write_to_log_file(list(retval), URL_LOG_PATH, "url-log-{}.log")
    else:
        logger.error(set_color(
            "unable to extract URL's from results...", level=40
        ))
