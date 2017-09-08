import os
import time
import urllib

import requests
from selenium import webdriver
from pyvirtualdisplay import Display
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.common.proxy import *

from lib.settings import (
    logger,
    set_color,
    proxy_string_to_dict,
    DEFAULT_USER_AGENT,
    URL_QUERY_REGEX,
    URL_REGEX,
    shutdown,
    create_dir,
)


def get_urls(query, url, verbose=False, warning=True, user_agent=None, proxy=None, **kwargs):
    """
      Bypass Google captchas and Google API by using selenium-webdriver to gather
      the Google URL. This will open a robot controlled browser window and attempt
      to get a URL from Google that will be used for scraping afterwards.

      Only downside to this method is that your IP and user agent will be visible
      until the application pulls the URL.
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
            ''.join(proxy_type): proxy[''.join(proxy_type)]
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
    if verbose:
        logger.debug(set_color(
            "found current URL from selenium browser '{}'...".format(retval), level=10
        ))
    logger.info(set_color(
        "closing the browser and continuing process.."
    ))
    browser.close()
    ff_display.stop()
    return retval


def parse_search_results(
        query, url, verbose=False, dirname="{}/log/url-log", filename="url-log-{}.log", **kwargs):
    """
      Parse a webpage from Google for URL's with a GET(query) parameter
    """
    exclude = "google" or "webcache" or "youtube"

    create_dir(dirname.format(os.getcwd()))
    full_file_path = "{}/{}".format(
        dirname.format(os.getcwd()), filename.format(len(os.listdir(dirname.format(
            os.getcwd()
        ))) + 1)
    )

    if verbose:
        logger.debug(set_color(
            "checking for user-agent and proxy configuration...", level=10
        ))
    try:
        proxy_string = kwargs.get("proxy")
    except:
        pass
    try:
        user_agent = kwargs.get("agent")
    except:
        pass
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
        proxy_string_info = proxy_string_info.format(''.join(proxy_string.keys()) + "://" + ''.join(proxy_string.values()))
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
        query_url = get_urls(query, url, verbose=verbose, user_agent=user_agent, proxy=proxy_string)
    except Exception as e:
        if "WebDriverException" in str(e):
            logger.exception(set_color(
                "it seems that you exited the browser, please allow the browser "
                "to complete it's run so that Zeus can bypass captchas and API "
                "calls", level=50
            ))
        else:
            logger.exception(set_color(
                "{} failed to gather the URL from search engine, caught exception '{}' "
                "exception has been logged to current log file...".format(
                    os.path.basename(__file__), str(e).strip()), level=50)
            )
        shutdown()
    logger.info(set_color(
        "URL successfully gathered, searching for GET parameters..."
    ))
    logger.info(set_color(proxy_string_info))
    req = requests.get(query_url, proxies=proxy_string)
    logger.info(set_color(user_agent_info))
    req.headers.update(headers)
    found_urls = URL_REGEX.findall(req.text)
    retval = set()
    for urls in list(found_urls):
        for url in list(urls):
            url = urllib.unquote(url)
            if URL_QUERY_REGEX.match(url) and exclude not in url:
                if type(url) is unicode:
                    url = str(url).encode("utf-8")
                if verbose:
                    logger.debug(set_color(
                        "found '{}'...".format(url), level=10
                    ))
                retval.add(url.split("&amp;")[0])
    logger.info(set_color(
        "found a total of {} URL's with a GET parameter...".format(len(retval))
    ))
    if len(retval) != 0:
        logger.info(set_color(
            "saving found URL's under '{}'...".format(full_file_path)
        ))
        with open(full_file_path, "a+") as log:
            for url in list(retval):
                log.write(url + "\n")
    else:
        logger.critical(set_color(
            "did not find any usable URL's with the given query '{}' "
            "using search engine '{}'...".format(query, url), level=50
        ))
    return list(retval) if len(retval) != 0 else None
