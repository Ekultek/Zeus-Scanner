import os
import re
import time
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

from var.auto_issue.github import request_issue_creation
from lib.settings import (
    logger,
    set_color,
    proxy_string_to_dict,
    DEFAULT_USER_AGENT,
    URL_QUERY_REGEX,
    URL_REGEX,
    shutdown,
    URL_LOG_PATH,
    write_to_log_file,
    get_proxy_type
)

try:
    unicode
except NameError:
    unicode = str


def bypass_ip_block(url, content_sep=("continue=", "Fid", "%")):
    """
    bypass Google's IP blocking by extracting the true URL from the ban URL.
    """

    def __add_https(data):
        if "https://" in data:
            return data
        else:
            return "https://{}".format(url.split("://")[-1])

    if isinstance(url, unicode):
        url = str(url)
    content_list_start = []
    content_list_end = []
    if content_sep[0] in url:
        data_list = url.split(content_sep[0])
        url_to_use = data_list[1]
    else:
        url_to_use = url

    for match in re.finditer(content_sep[1], url_to_use):
        content_list_start.append((match.start(), match.end()))
    splice_to_use = content_list_start[-1][-1]

    for match in re.finditer(content_sep[2], url[0:splice_to_use]):
        content_list_end.append((match.start(), match.end()))
    try:
        return __add_https(url[0:content_list_end[-1][-1] - 1])
    except:
        return url


def extract_webcache_url(webcache_url, splitter="+"):
    webcache_url = unquote(webcache_url)
    webcache_regex = re.compile(r"cache:(.{,16})?:")
    data = webcache_regex.split(webcache_url)
    to_extract = data[2].split(splitter)
    extracted_to_test = to_extract[0]
    if URL_REGEX.match(extracted_to_test):
        return extracted_to_test
    return None


def get_urls(query, url, verbose=False, warning=True, user_agent=None, proxy=None, **kwargs):
    """
      Bypass Google captchas and Google API by using selenium-webdriver to gather
      the Google URL. This will open a robot controlled browser window and attempt
      to get a URL from Google that will be used for scraping afterwards.
    """
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
    search.send_keys(query)
    search.send_keys(Keys.RETURN)  # hit return after you enter search text
    time.sleep(3)
    if verbose:
        logger.debug(set_color(
            "obtaining URL from selenium..."
        ))
    retval = browser.current_url
    ban_url_schema = ["http://ipv6.google.com", "http://ipv4.google.com"]
    if any(u in retval for u in ban_url_schema):  # if you got IP banned
        logger.warning(set_color(
            "it appears that Google is attempting to block your IP address, attempting bypass...", level=30
        ))
        try:
            retval = bypass_ip_block(retval)
        except Exception as e:
            browser.close()  # stop all the random rogue processes
            ff_display.stop()
            logger.exception(set_color(
                "zeus was unable to extract the correct URL from the ban URL '{}'...".format(
                    unquote(retval)
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


def parse_search_results(
        query, url_to_search, verbose=False, **kwargs):
    """
      Parse a webpage from Google for URL's with a GET(query) parameter
    """
    exclude = (
        "www.google.com", "map.google.com", "mail.google.com", "drive.google.com",
        "news.google.com", "accounts.google.com"
    )
    splitter = "&amp;"
    retval = set()
    query_url = None

    def __get_headers():
        proxy_string, user_agent = None, None
        try:
            proxy_string = kwargs.get("proxy")
        except:
            pass

        try:
            user_agent = kwargs.get("agent")
        except:
            pass

        return proxy_string, user_agent

    if verbose:
        logger.debug(set_color(
            "checking for user-agent and proxy configuration...", level=10
        ))
    proxy_string, user_agent = __get_headers()

    if proxy_string is None:
        proxy_string = None
    else:
        proxy_string = proxy_string_to_dict(proxy_string)
    if user_agent is None:
        user_agent = DEFAULT_USER_AGENT
    else:
        user_agent = user_agent

    user_agent_info = "adjusting user-agent header to {}..."
    if user_agent is not DEFAULT_USER_AGENT:
        user_agent_info = user_agent_info.format(user_agent.strip())
    else:
        user_agent_info = user_agent_info.format("default user agent '{}'".format(DEFAULT_USER_AGENT))

    proxy_string_info = "setting proxy to {}..."
    if proxy_string is not None:
        proxy_string_info = proxy_string_info.format(
            ''.join(proxy_string.keys()) + "://" + ''.join(proxy_string.values()))
    else:
        proxy_string_info = "no proxy configuration detected..."

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
        if "WebDriverException" in str(e):
            logger.exception(set_color(
                "it seems that you exited the browser, please allow the browser "
                "to complete it's run so that Zeus can bypass captchas and API "
                "calls", level=50
            ))
        elif "'/usr/lib/firefoxdriver/webdriver.xpi'" in str(e):
            logger.fatal(set_color(
                "firefox was not found in the default location on your system, "
                "check your installation and make sure it is in /usr/lib, if you "
                "find it there, restart your system and try again...", level=50
            ))
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
    url_skip_schema = ("maps.google", "play.google", "youtube")
    for urls in list(found_urls):
        for url in list(urls):
            url = unquote(url)
            if not any(u in url for u in url_skip_schema):
                if URL_QUERY_REGEX.match(url) and not any(l in url for l in exclude):
                    if isinstance(url, unicode):
                        url = str(url).encode("utf-8")
                    if "webcache" in url:
                        logger.info(set_color(
                            "received webcache URL, extracting URL from webcache..."
                        ))
                        webcache_url = url
                        url = extract_webcache_url(webcache_url)
                        if url is None:
                            logger.warning(set_color(
                                "unable to extract url from given webcache URL '{}'...".format(
                                    webcache_url
                                ), level=30
                            ))
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
                        retval.add(url.split("&amp;")[0])
    logger.info(set_color(
        "found a total of {} URL's with a GET parameter...".format(len(retval))
    ))
    if len(retval) != 0:
        write_to_log_file(retval, URL_LOG_PATH, "url-log-{}.log")
    else:
        logger.critical(set_color(
            "did not find any usable URL's with the given query '{}' "
            "using search engine '{}'...".format(query, url_to_search), level=50
        ))
        shutdown()
    return list(retval) if len(retval) != 0 else None


def search_multiple_pages(query, link_amount, proxy=None, agent=None, verbose=False):

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
