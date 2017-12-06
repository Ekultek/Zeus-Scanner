import os
import time

try:
    from urllib import (  # python 2
        unquote
    )
except ImportError:
    from urllib.parse import (  # python 3
        unquote
    )

import requests
from bs4 import BeautifulSoup
from pyvirtualdisplay import Display
from requests.exceptions import ConnectionError
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.remote.errorhandler import (
    UnexpectedAlertPresentException,
    ElementNotInteractableException,
)

import var.search
from var.auto_issue.github import request_issue_creation
from lib.core.common import (
    write_to_log_file,
    HTTP_HEADER,
    URLParser,
    shutdown,
    prompt,
    run_fix
)
from lib.core.settings import (
    logger,
    set_color,
    proxy_string_to_dict,
    DEFAULT_USER_AGENT,
    URL_QUERY_REGEX,
    URL_REGEX,
    URL_LOG_PATH,
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
    BLACKLIST_FILE_PATH,
    calculate_success,
    REINSTALL_TOOL,
    EXTRACTED_URL_FILENAME,
    URL_FILENAME,
    BLACKLIST_FILENAME,
    IP_BAN_REGEX
)

try:
    unicode
except NameError:
    unicode = str


def get_urls(query, url, verbose=False, **kwargs):
    """
      Bypass Google captchas and Google API by using selenium-webdriver to gather
      the Google URL. This will open a robot controlled browser window and attempt
      to get a URL from Google that will be used for scraping afterwards.
    """
    query = query.decode('unicode_escape').encode('utf-8')
    proxy, user_agent = kwargs.get("proxy", None), kwargs.get("user_agent", None)
    tor, tor_port = kwargs.get("tor", False), kwargs.get("tor_port", None)
    batch = kwargs.get("batch", False)
    xforward = kwargs.get("xforward", False)
    logger.info(set_color(
        "setting up virtual display to hide the browser..."
    ))
    ff_display = Display(visible=0, size=(800, 600))
    ff_display.start()
    browser = var.search.SetBrowser(agent=user_agent, proxy=proxy, tor=tor, xforward=xforward).set_browser()
    logger.info(set_color("browser will open shortly...", level=25))
    browser.get(url)
    if verbose:
        logger.debug(set_color(
            "searching search engine for the 'q' element (search button)...", level=10
        ))
    search = browser.find_element_by_name('q')
    logger.info(set_color(
        "searching search engine using query '{}'...".format(query)
    ))
    try:
        # enter the text you want to search and hit enter
        search.send_keys(query)
        search.send_keys(Keys.RETURN)
        if not tor:
            time.sleep(3)
        else:
            logger.warning(set_color(
                "sleep time has been increased to 10 seconds due to tor being used...", level=30
            ))
            time.sleep(10)
    except ElementNotInteractableException:
        # get rid of the popup box and hit enter after entering the text to search
        browser.execute_script("document.querySelectorAll('label.boxed')[1].click()")
        search.send_keys(query)
        search.send_keys(Keys.RETURN)
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
        # discover the alert and close it before continuing
        alert = browser.switch_to.alert
        alert.accept()
        retval = browser.current_url
    # if you have been IP banned, we'll extract the URL from it
    if IP_BAN_REGEX.search(retval) is not None:
        logger.warning(set_color(
            "it appears that Google is attempting to block your IP address, attempting bypass...", level=30
        ))
        try:
            retval = URLParser(retval).extract_ip_ban_url()
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
                    question_msg, opts="yN", default="y"
                )

            # shutdown and write the URL to a file
            if not str(do_continue).lower().startswith("n"):
                write_to_log_file(retval, EXTRACTED_URL_LOG, EXTRACTED_URL_FILENAME)
                logger.info(set_color(
                    "it is advised to extract the URL's from the produced URL written to the above "
                    "(IE open the log, copy the url into firefox)...".format(retval)
                ))
                shutdown()
        except Exception as e:
            # stop all the random rogue processes, this isn't guaranteed to stop the processes
            # that's why we have the clean up script in case this fails
            browser.close()
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
    possible_leftovers = URLParser(None).possible_leftovers
    splitter = "&amp;"
    retval = set()
    query_url = None

    parse_webcache, pull_all = kwargs.get("parse_webcache", False), kwargs.get("pull_all", False)
    proxy_string, user_agent = kwargs.get("proxy", None), kwargs.get("agent", None)
    forward_for = kwargs.get("forward_for", False)
    tor = kwargs.get("tor", False)
    batch = kwargs.get("batch", False)
    show_success = kwargs.get("show_success", False)

    if verbose:
        logger.debug(set_color(
            "parsing blacklist...", level=10
        ))
    parse_blacklist(query, BLACKLIST_FILE_PATH, batch=batch)

    if verbose:
        logger.debug(set_color(
            "checking for user-agent and proxy configuration...", level=10
        ))

    if not parse_webcache and "google" in url_to_search:
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
            HTTP_HEADER.CONNECTION: "close",
            HTTP_HEADER.USER_AGENT: user_agent,
            HTTP_HEADER.X_FORWARDED_FOR: "{}, {}, {}".format(ip_to_use[0], ip_to_use[1], ip_to_use[2])
        }
    else:
        headers = {
            HTTP_HEADER.CONNECTION: "close",
            HTTP_HEADER.USER_AGENT: user_agent
        }
    logger.info(set_color(
        "attempting to gather query URL..."
    ))
    try:
        query_url = get_urls(
            query, url_to_search, verbose=verbose, user_agent=user_agent, proxy=proxy_string,
            tor=tor, batch=batch, xforward=forward_for
        )
    except Exception as e:
        if "'/usr/lib/firefoxdriver/webdriver.xpi'" in str(e):
            logger.fatal(set_color(
                "firefox was not found in the default location on your system, "
                "check your installation and make sure it is in /usr/lib, if you "
                "find it there, restart your system and try again...", level=50
            ))
        elif "connection refused" in str(e).lower():
            logger.fatal(set_color(
                "there are to many sessions of firefox opened and selenium cannot "
                "create a new one...", level=50
            ))
            run_fix(
                "would you like to attempt to auto clean the open sessions",
                "sudo sh {}".format(CLEANUP_TOOL_PATH),
                "kill off the open sessions of firefox and re-run Zeus...",
                exit_process=True
            )
        elif "Program install error!" in str(e):
            logger.error(set_color(
                "seems the program is having some trouble installing would you like "
                "to try and automatically fix this issue", level=40
            ))
            run_fix(
                "would you like to attempt to fix this issue automatically",
                "sudo sh {}".format(FIX_PROGRAM_INSTALL_PATH),
                "you can manually try and re-install Xvfb to fix the problem...",
                exit_process=True
            )
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
        elif "Unable to find a matching set of capabilities" in str(e):
            logger.fatal(set_color(
                "it appears that firefox, selenium, and geckodriver are not playing nice with one another...", level=50
            ))
            run_fix(
                "would you like to attempt to resolve this issue automatically",
                "sudo sh {}".format(REINSTALL_TOOL),
                ("you will need to reinstall firefox to a later version, update selenium, and reinstall the "
                 "geckodriver to continue using Zeus..."),
                exit_process=True
            )
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

    try:
        req = requests.get(query_url, proxies=proxy_string, params=headers)
    except ConnectionError:
        logger.warning(set_color(
            "target machine refused connection, delaying and trying again...", level=30
        ))
        time.sleep(3)
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
            url = URLParser(url).strip_url_leftovers()
        if parse_webcache:
            if "webcache" in url:
                logger.info(set_color(
                    "found a webcache URL, extracting..."
                ))
                url = URLParser(url).extract_webcache_url()
                if verbose:
                    logger.debug(set_color(
                        "found '{}'...".format(url), level=15
                    ))
                true_retval.add(url)
            else:
                true_retval.add(url)
        else:
            true_retval.add(url)

    if len(true_retval) != 0:
        file_path = write_to_log_file(true_retval, URL_LOG_PATH, URL_FILENAME)
        if show_success:
            amount_of_urls = len(open(file_path).readlines())
            success_rate = calculate_success(amount_of_urls)
            logger.info(set_color(
                "provided query has a {} success rate...".format(success_rate)
            ))
    else:
        logger.fatal(set_color(
            "did not find any URLs with given query '{}' writing query to blacklist...".format(query), level=50
        ))
        write_to_log_file(query, BLACKLIST_FILE_PATH, BLACKLIST_FILENAME, blacklist=True)
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
    batch = kwargs.get("batch", False)
    show_success = kwargs.get("show_success", False)
    attrib, desc = "a", "href"
    retval = set()
    search_engine = AUTHORIZED_SEARCH_ENGINES["search-results"]

    logger.warning(set_color(
        "searching multiple pages will not be done on Google...".format(search_engine), level=30
    ))

    if not parse_blacklist(query, BLACKLIST_FILE_PATH, batch=batch):
        shutdown()

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
        write_to_log_file(retval, URL_LOG_PATH, URL_FILENAME)
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

    if len(retval) > 0:
        logger.info(set_color(
            "a total of {} URL(s) found out of the requested {}...".format(len(retval), link_amount), level=25
        ))
        file_path = write_to_log_file(retval, URL_LOG_PATH, URL_FILENAME)
        if show_success:
            amount_of_urls = len(open(file_path).readlines())
            success_rate = calculate_success(amount_of_urls)
            logger.info(set_color(
                "provided query has a {} success rate...".format(success_rate)
            ))
        return list(retval)
    else:
        logger.warning(set_color(
            "did not find any links with given query '{}' writing to blacklist...".format(query), level=30
        ))
        write_to_log_file(query, BLACKLIST_FILE_PATH, BLACKLIST_FILENAME)
