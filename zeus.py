#!/usr/bin/env python

import io
import sys
import time
import shlex
import warnings
import subprocess
from importlib import reload

from var import blackwidow
from var.search import selenium_search
from var.auto_issue.github import request_issue_creation
from lib.header_check import main_header_check

from lib.core.parse import ZeusParser
from lib.core.errors import (
    InvalidInputProvided,
    InvalidProxyType,
    ZeusArgumentException
)
from lib.core.common import (
    start_up,
    shutdown,
    prompt
)
from lib.core.settings import (
    setup,
    logger,
    set_color,
    get_latest_log_file,
    get_random_dork,
    fix_log_file,
    config_headers,
    config_search_engine,
    find_running_opts,
    run_attacks,
    CURRENT_LOG_FILE_PATH,
    SPIDER_LOG_PATH,
    URL_REGEX, URL_QUERY_REGEX,
    URL_LOG_PATH,
    BANNER
)

warnings.simplefilter("ignore")

if __name__ == "__main__":

    # this will take care of most of the Unicode errors.
    reload(sys)
    sys.setrecursionlimit(1500)

    opt = ZeusParser.cmd_parser()

    ZeusParser().single_show_args(opt)

    # verify all the arguments passed before we continue
    # with the process
    ZeusParser().verify_args()

    # run the setup on the program
    setup(verbose=opt.runInVerbose)

    if not opt.hideBanner:
        print(BANNER)

    start_up()

    if opt.runInVerbose:
        being_run = find_running_opts(opt)
        logger.debug(set_color(
            "Running with options '{}'".format(being_run), level=10
        ))

    logger.info(set_color(
        "Log file being saved to '{}'".format(get_latest_log_file(CURRENT_LOG_FILE_PATH))
    ))


    def __run_attacks_main(**kwargs):
        """
        Main method to run the attacks
        """
        log_to_use = kwargs.get("log", None)
        if log_to_use is None:
            options = (opt.dorkToUse, opt.useRandomDork, opt.dorkFileToUse)
            log_to_use = URL_LOG_PATH if any(o for o in options) else SPIDER_LOG_PATH
            try:
                urls_to_use = get_latest_log_file(log_to_use)
            except TypeError:
                urls_to_use = None
        else:
            urls_to_use = log_to_use

        if urls_to_use is None:
            logger.error(set_color(
                "Unable to run attacks appears that no file was created for the retrieved data", level=40
            ))
            shutdown()
        options = [
            opt.runSqliScan, opt.runPortScan,
            opt.adminPanelFinder, opt.runXssScan,
            opt.performWhoisLookup, opt.performClickjackingScan,
            opt.pgpLookup
        ]
        if any(options):
            with open(urls_to_use) as urls:
                for i, url in enumerate(urls.readlines(), start=1):
                    current = i
                    if "webcache" in url:
                        logger.warning(set_color(
                            "Ran into unexpected webcache URL skipping", level=30
                        ))
                        current -= 1
                    else:
                        if not url.strip() == "http://" or url == "https://":
                            logger.info(set_color(
                                "Currently running on '{}' (target #{})".format(
                                    url.strip(), current
                                ), level=25
                            ))
                            logger.info(set_color(
                                "Fetching target meta-data"
                            ))
                            identified = main_header_check(
                                url, verbose=opt.runInVerbose, agent=agent_to_use,
                                proxy=proxy_to_use, xforward=opt.forwardedForRandomIP,
                                identify_plugins=opt.identifyPlugin, identify_waf=opt.identifyProtection,
                                show_description=opt.showPluginDescription
                            )
                            if not identified:
                                logger.error(set_color(
                                    "Target is refusing to allow meta-data dumping, skipping", level=40
                                ))
                            run_attacks(
                                url.strip(),
                                sqlmap=opt.runSqliScan, nmap=opt.runPortScan, pgp=opt.pgpLookup,
                                xss=opt.runXssScan, whois=opt.performWhoisLookup, admin=opt.adminPanelFinder,
                                clickjacking=opt.performClickjackingScan, github=opt.searchGithub,
                                verbose=opt.runInVerbose, batch=opt.runInBatch,
                                auto_start=opt.autoStartSqlmap, xforward=opt.forwardedForRandomIP,
                                sqlmap_args=opt.sqlmapArguments, nmap_args=opt.nmapArguments,
                                show_all=opt.showAllConnections, do_threading=opt.threadPanels,
                                tamper_script=opt.tamperXssPayloads, timeout=opt.controlTimeout,
                                proxy=proxy_to_use, agent=agent_to_use, conf_file=opt.sqlmapConfigFile,
                                threads=opt.amountOfThreads, force_ssl=opt.forceSSL
                            )
                            print("\n")
                        else:
                            logger.warning(set_color(
                                "Malformed URL discovered, skipping", level=30
                            ))


    proxy_to_use, agent_to_use = config_headers(
        proxy=opt.proxyConfig, proxy_file=opt.proxyFileRand,
        p_agent=opt.usePersonalAgent, rand_agent=opt.useRandomAgent,
        verbose=opt.runInVerbose
    )
    search_engine = config_search_engine(
        verbose=opt.runInVerbose, ddg=opt.useDDG,
        aol=opt.useAOL, bing=opt.useBing, enum=opt.fileToEnumerate
    )

    try:
        # use a personal dork as the query
        if opt.dorkToUse is not None and not opt.searchMultiplePages:
            logger.info(set_color(
                "Starting dork scan with query '{}'".format(opt.dorkToUse)
            ))
            try:
                selenium_search.parse_search_results(
                    opt.dorkToUse, search_engine, verbose=opt.runInVerbose, proxy=proxy_to_use,
                    agent=agent_to_use, pull_all=opt.noExclude, parse_webcache=opt.parseWebcache,
                    forward_for=opt.forwardedForRandomIP, tor=opt.useTor, batch=opt.runInBatch,
                    show_success=opt.showSuccessRate
                )
            except InvalidProxyType:
                supported_proxy_types = ("socks5", "socks4", "https", "http")
                logger.fatal(set_color(
                    "The provided proxy is not valid, please specify the protocol and try again. "
                    "Supported proxy protocols are {} (IE socks5://127.0.0.1:9050)".format(
                        ", ".join(list(supported_proxy_types))), level=50
                ))
            except Exception as e:
                if "Permission denied:" in str(e):
                    logger.fatal(set_color(
                        "Your permissions are not allowing Zeus to run, "
                        "try running Zeus with sudo", level=50
                    ))
                    shutdown()
                else:
                    logger.exception(set_color(
                        "Ran into exception '{}'".format(e), level=50
                    ))
                request_issue_creation()
                pass

            __run_attacks_main()

        # search multiple pages of Google
        elif opt.dorkToUse is not None or opt.useRandomDork and opt.searchMultiplePages:
            if opt.dorkToUse is not None:
                dork_to_use = opt.dorkToUse
            elif opt.useRandomDork:
                dork_to_use = get_random_dork()
            else:
                dork_to_use = None

            if dork_to_use is None:
                logger.warning(set_color(
                    "There has been no dork specified to do the searching, defaulting to random dork", level=30
                ))
                dork_to_use = get_random_dork()

            dork_to_use = dork_to_use.strip()

            if opt.amountToSearch is None:
                logger.warning(set_color(
                    "Did not specify amount of links to find, defaulting to 75", level=30
                ))
                link_amount_to_search = 75
            else:
                link_amount_to_search = opt.amountToSearch

            logger.info(set_color(
                "Searching Google using dork '{}' for a total of {} links".format(
                    dork_to_use, link_amount_to_search
                )
            ))
            try:
                selenium_search.search_multiple_pages(
                    dork_to_use, link_amount_to_search, proxy=proxy_to_use,
                    agent=agent_to_use, verbose=opt.runInVerbose,
                    xforward=opt.forwardedForRandomIP, batch=opt.runInBatch,
                    show_success=opt.showSuccessRate
                )
            except Exception as e:
                if "Error 400" in str(e):
                    logger.fatal(set_color(
                        "Failed to connect to search engine".format(e), level=50
                    ))
                else:
                    logger.exception(set_color(
                        "Failed with unexpected error '{}'".format(e), level=50
                    ))
                shutdown()

            __run_attacks_main()

        # use a file full of dorks as the queries
        elif opt.dorkFileToUse is not None:
            with io.open(opt.dorkFileToUse, encoding="utf-8") as dorks:
                for dork in dorks.readlines():
                    dork = dork.strip()
                    logger.info(set_color(
                        "Starting dork scan with query '{}'".format(dork)
                    ))
                    try:
                        selenium_search.parse_search_results(
                            dork, search_engine, verbose=opt.runInVerbose, proxy=proxy_to_use,
                            agent=agent_to_use, pull_all=opt.noExclude, parse_webcache=opt.parseWebcache,
                            tor=opt.useTor, batch=opt.runInBatch
                        )
                    except Exception as e:
                        logger.exception(set_color(
                            "Ran into exception '{}'".format(e), level=50
                        ))
                        request_issue_creation()
                        pass

            __run_attacks_main()

        # use a random dork as the query
        elif opt.useRandomDork:
            random_dork = get_random_dork().strip()
            if opt.runInVerbose:
                logger.debug(set_color(
                    "Choosing random dork from etc/dorks.txt", level=10
                ))
            logger.info(set_color(
                "Using random dork '{}' as the search query".format(random_dork)
            ))
            try:
                selenium_search.parse_search_results(
                    random_dork, search_engine, verbose=opt.runInVerbose,
                    proxy=proxy_to_use, agent=agent_to_use, pull_all=opt.noExclude, parse_webcache=opt.parseWebcache,
                    tor=opt.useTor, batch=opt.runInBatch
                )
                __run_attacks_main()

            except Exception as e:
                logger.exception(set_color(
                    "Ran into exception '{}' and cannot continue, saved to current log file".format(e),
                    level=50
                ))
                request_issue_creation()
                pass

        # spider a given webpage for all available URL's
        elif opt.spiderWebSite:
            problem_identifiers = ["http://", "https://"]
            if not URL_REGEX.match(opt.spiderWebSite):
                err_msg = "URL did not match a true URL{}"
                if not any(m in opt.spiderWebSite for m in problem_identifiers):
                    err_msg = err_msg.format(" issue seems to be that http:// "
                                             "or https:// is not present in the URL")
                else:
                    err_msg = err_msg.format("")
                raise InvalidInputProvided(
                    err_msg
                )
            else:
                if URL_QUERY_REGEX.match(opt.spiderWebSite):
                    question_msg = (
                        "It is recommended to not use a URL that has a GET (query) parameter in it, "
                        "would you like to continue? > "
                    )
                    if not opt.runInBatch:
                        is_sure = prompt(
                            question_msg, opts="yN"
                        )
                    else:
                        is_sure = prompt(
                            question_msg, opts="yN", default="y"
                        )
                    if is_sure.lower().startswith("y"):
                        pass
                    else:
                        shutdown()

            blackwidow.blackwidow_main(opt.spiderWebSite, agent=agent_to_use, proxy=proxy_to_use,
                                       verbose=opt.runInVerbose, forward=opt.forwardedForRandomIP)

            __run_attacks_main()

        # enumerate a file and run attacks on the URL's provided
        elif opt.fileToEnumerate is not None:
            logger.info(set_color(
                "Found a total of {} URLs to enumerate in given file".format(
                    len(open(opt.fileToEnumerate).readlines())
                )
            ))
            __run_attacks_main(log=opt.fileToEnumerate)

        else:
            logger.warning(set_color(
                "Failed to provide a mandatory argument, you will be redirected to the help menu\n", level=30
            ))
            time.sleep(2)
            zeus_help_menu_command = shlex.split("python3 zeus.py --help")
            subprocess.call(zeus_help_menu_command)
    except IOError as e:
        if "Invalid URL" in str(e):
            logger.exception(set_color(
                "URL provided is not valid, schema appears to be missing", level=50
            ))
            request_issue_creation()
            shutdown()
        elif "HTTP Error 429: Too Many Requests" in str(e):
            logger.fatal(set_color(
                "WhoIs doesn't like it when you send to many requests at one time, "
                "try updating the timeout with the --time-sec flag (IE --time-sec 10)", level=50
            ))
            shutdown()
        elif "No such file or directory" in str(e):
            logger.fatal(set_color(
                "Provided file does not exist, make sure you have the full path", level=50
            ))
            shutdown()
        else:
            logger.exception(set_color(
                "Zeus has hit an unexpected error and cannot continue, error code '{}'".format(e), level=50
            ))
            request_issue_creation()
    except KeyboardInterrupt:
        logger.fatal(set_color(
            "User aborted process", level=50
        ))
        shutdown()
    except UnboundLocalError:
        logger.warning(set_color(
            "Do not interrupt the browser when selenium is running, "
            "it will cause Zeus to crash", level=30
        ))
    except ZeusArgumentException:
        shutdown()
    except Exception as e:
        if "url did not match a true url" in str(e).lower():
            logger.error(set_color(
                "You did not provide a URL that is capable of being processed, "
                "the URL provided to the spider needs to contain protocol as well "
                "ie. 'http://google.com' (it is advised not to add the GET parameter), "
                "fix the URL you want to scan and try again", level=40
            ))
            shutdown()
        elif "Service geckodriver unexpectedly exited" in str(e):
            logger.fatal(set_color(
                "it seems your firefox version is not compatible with the geckodriver version, "
                "please re-install Zeus and try again", level=50
            ))
            shutdown()
        elif "Max retries exceeded with url" in str(e):
            logger.fatal(set_color(
                "You have hit the max retries, to continue using Zeus "
                "it is recommended to use a proxy (--proxy/--proxy-file) "
                "along with a new user-agent (--random-agent/--agent).", level=50
            ))
            shutdown()
        else:
            logger.exception(set_color(
                "Ran into exception '{}' exception has been saved to log file".format(e), level=50
            ))
            request_issue_creation()

    # fix the log file before shutting down incase you want to look at it
    fix_log_file()
shutdown()
