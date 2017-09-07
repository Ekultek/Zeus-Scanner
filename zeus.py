#!/usr/bin/env python

import time
import optparse
import subprocess
import httplib as http_client

from var.google_search import search
from lib.attacks.sqlmap_scan.sqlmap_opts import SQLMAP_API_OPTIONS
from lib.attacks import (
    nmap_scan,
    sqlmap_scan
)
from lib.settings import (
    setup,
    BANNER,
    start_up,
    shutdown,
    logger,
    set_color,
    get_latest_log_file,
    grab_random_agent,
    CURRENT_LOG_FILE_PATH,
    AUTHORIZED_SEARCH_ENGINES,
    URL_LOG_PATH,
    replace_http,
)

if __name__ == "__main__":

    parser = optparse.OptionParser(usage="zeus.py -[d|l] [OPTIONS]")

    # mandatory options
    mandatory = optparse.OptionGroup(parser, "Mandatory Options",
                                     "These options have to be used in order for Zeus to run")
    mandatory.add_option("-d", "--dork", dest="dorkToUse", metavar="DORK",
                         help="Specify a singular Google dork to use for queries")
    mandatory.add_option("-l", "--dork-list", dest="dorkFileToUse", metavar="FILE-PATH",
                         help="Specify a file full of dorks to run through"),

    # attack options
    attacks = optparse.OptionGroup(parser, "Attack arguments",
                                   "These arguments will give you the choice on how you want to check the websites")
    attacks.add_option("-s", "--sqli", dest="runSqliScan", action="store_true",
                       help="Run a Sqlmap SQLi scan on the discovered URL's")
    attacks.add_option("-p", "--port-nmap_scan", dest="runPortScan", action="store_true",
                       help="Run a Nmap port scan on the discovered URL's")

    # search engine options
    engines = optparse.OptionGroup(parser, "Search engine arguments",
                                   "Arguments to change the search engine used (default is Google)")
    engines.add_option("-D", "--search-engine-ddg", dest="useDDG", action="store_true",
                       help="Use DuckDuckGo as the search engine")
    engines.add_option("-B", "--search-engine-bing", dest="useBing", action="store_true",
                       help="Use Bing as the search engine")
    engines.add_option("-A", "--search-engine-aol", dest="useAOL", action="store_true",
                       help="Use AOL as the search engine")

    # miscellaneous options
    misc = optparse.OptionGroup(parser, "Misc Options",
                                "These options affect how the program will run")
    misc.add_option("--verbose", dest="runInVerbose", action="store_true",
                    help="Run the application in verbose mode (more output)")
    misc.add_option("--proxy", dest="proxyConfig", metavar="PROXY-STRING",
                    help="Use a proxy to do the scraping, will not auto configure "
                         "to the API's")
    misc.add_option("--random-agent", dest="useRandomAgent", action="store_true",
                    help="Use a random user-agent from the etc/agents.txt file")
    misc.add_option("--agent", dest="usePersonalAgent", metavar="USER-AGENT",
                    help="Use your own personal user-agent")
    misc.add_option("--show-requests", dest="showRequestInfo", action="store_true",
                    help="Show your request information (more verbose output) this "
                         "will also show all requests made to the API's used")
    misc.add_option("--sqlmap-args", dest="sqlmapArguments", metavar="SQLMAP-ARGS",
                    help="Pass the arguments to send to the sqlmap API within quotes & "
                         "separated by a comma. IE 'dbms mysql, verbose 3, level 5'")
    misc.add_option("--auto-start", dest="autoStartSqlmap", action="store_true",
                    help="Attempt to automatically find sqlmap on your system")
    misc.add_option("--search-here", dest="givenSearchPath", metavar="PATH-TO-START",
                    help="Start searching for sqlmap in this given path")
    misc.add_option("--show", dest="showSqlmapArguments", action="store_true",
                    help="Show the arguments that the sqlmap API understands")

    parser.add_option_group(mandatory)
    parser.add_option_group(attacks)
    parser.add_option_group(engines)
    parser.add_option_group(misc)

    opt, _ = parser.parse_args()

    # run the setup on the program
    setup(verbose=opt.runInVerbose)

    print(BANNER)

    start_up()

    if opt.showSqlmapArguments:
        logger.info(set_color(
            "there are a total of {} arguments understood by sqlmap API, "
            "they include:".format(len(SQLMAP_API_OPTIONS))
        ))
        print("\n")
        for arg in SQLMAP_API_OPTIONS:
            print(
                "[*] {}".format(arg)
            )
        shutdown()

    def __find_running_opts():
        """
        display the running options if verbose is used
        """
        opts_being_used = []
        for o, v in opt.__dict__.items():
            if v is not None:
                opts_being_used.append((o, v))
        return dict(opts_being_used)

    if opt.runInVerbose:
        being_run = __find_running_opts()
        logger.debug(set_color(
            "running with options '{}'...".format(being_run), level=10
        ))

    logger.info(set_color(
        "log file being saved to '{}'...".format(get_latest_log_file(CURRENT_LOG_FILE_PATH))
    ))

    if opt.showRequestInfo:
        logger.debug(set_color(
            "showing all HTTP requests because --show-requests flag was used...", level=10
        ))
        http_client.HTTPConnection.debuglevel = 1

    def __config_headers():
        """
        configure the request headers, this will configure user agents and proxies
        """
        if opt.proxyConfig is not None:
            proxy = opt.proxyConfig
        else:
            proxy = None
        if opt.usePersonalAgent is not None:
            agent = opt.usePersonalAgent
        elif opt.useRandomAgent:
            agent = grab_random_agent(verbose=opt.runInVerbose)
        else:
            agent = None
        return proxy, agent

    def __config_search_engine(verbose=False):
        """
        configure the search engine if a one different from google is given
        """
        non_default_msg = "specified to use non-default search engine..."
        if opt.useDDG:
            if verbose:
                logger.debug(set_color(
                    "using DuckDuckGo as the search engine...", level=10
                ))
            logger.info(set_color(
                non_default_msg
            ))
            se = AUTHORIZED_SEARCH_ENGINES["duckduckgo"]
        elif opt.useAOL:
            if verbose:
                logger.debug(set_color(
                    "using AOL as the search engine...", level=10
                ))
            logger.info(set_color(
                non_default_msg
            ))
            se = AUTHORIZED_SEARCH_ENGINES["aol"]
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

    def __create_sqlmap_arguments():
        """
        create the sqlmap arguments (a list of tuples) that will be passed to the API
        """
        retval = []
        if opt.sqlmapArguments is not None:
            for line in opt.sqlmapArguments.split(","):
                to_use = line.strip().split(" ")
                option = (to_use[0], to_use[1])
                if to_use[0] in SQLMAP_API_OPTIONS:
                    retval.append(option)
                else:
                    logger.warning(set_color(
                        "option '{}' is not recognized by sqlmap API, skipping...".format(option[0]),
                        level=30
                    ))
        return retval

    proxy_to_use, agent_to_use = __config_headers()
    search_engine = __config_search_engine(verbose=opt.runInVerbose)

    try:
        if opt.dorkToUse is not None:
            logger.info(set_color(
                "starting dork scan with query '{}'...".format(opt.dorkToUse)
            ))
            try:
                search.parse_search_results(
                    opt.dorkToUse, search_engine, verbose=opt.runInVerbose, proxy=proxy_to_use,
                    agent=agent_to_use
                )
            except Exception as e:
                logger.exception(set_color(
                    "ran into exception '{}'...".format(e), level=50
                ))
                pass

            urls_to_use = get_latest_log_file(URL_LOG_PATH)
            with open(urls_to_use) as urls:
                for url in urls.readlines():
                    if opt.runSqliScan:
                        sqlmap_scan.sqlmap_scan_main(url.strip(), verbose=opt.runInVerbose,
                                                     opts=__create_sqlmap_arguments(),
                                                     auto_search=opt.autoStartSqlmap,
                                                     given_path=opt.givenSearchPath)
                    elif opt.runPortScan:
                        url_to_use = replace_http(url.strip())
                        nmap_scan.perform_port_scan(url_to_use, verbose=opt.runInVerbose)

        elif opt.dorkFileToUse is not None:
            with open(opt.dorkFileToUse) as dorks:
                for dork in dorks.readlines():
                    dork = dork.strip()
                    logger.info(set_color(
                        "starting dork scan with query '{}'...".format(dork)
                    ))
                    try:
                        search.parse_search_results(
                            dork, search_engine, verbose=opt.runInVerbose, proxy=proxy_to_use,
                            agent=agent_to_use
                        )
                    except Exception as e:
                        logger.exception(set_color(
                            "ran into exception '{}'...".format(e), level=50
                        ))
                        pass

            urls_to_use = get_latest_log_file(URL_LOG_PATH)
            with open(urls_to_use) as urls:
                for url in urls.readlines():
                    if opt.runSqliScan:
                        sqlmap_scan.sqlmap_scan_main(url.strip(), verbose=opt.runInVerbose,
                                                     opts=__create_sqlmap_arguments(),
                                                     auto_search=opt.autoStartSqlmap,
                                                     given_path=opt.givenSearchPath)
                    elif opt.runPortScan:
                        url_to_use = replace_http(url.strip())
                        nmap_scan.perform_port_scan(url_to_use, verbose=opt.runInVerbose)
        else:
            logger.critical(set_color(
                "failed to provide a mandatory argument, you will be redirected to the help menu...", level=50
            ))
            time.sleep(2)
            subprocess.call("python zeus.py --help", shell=True)

    except KeyboardInterrupt:
        logger.error(set_color(
            "user aborted process...", level=40
        ))
    except UnboundLocalError:
        logger.warning(set_color(
            "do not interrupt the browser when selenium is running, "
            "it will cause Zeus to crash...", level=30
        ))
    except Exception as e:
        logger.exception(set_color(
            "ran into exception '{}' exception has been saved to log file...".format(e)
        ))

shutdown()
