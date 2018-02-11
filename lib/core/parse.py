import sys
from optparse import (
    OptionParser,
    OptionGroup,
    SUPPRESS_HELP
)

import lib.core.settings
import lib.core.common
import lib.core.errors
import lib.attacks.nmap_scan.nmap_opts
import lib.attacks.sqlmap_scan.sqlmap_opts


class ZeusParser(OptionParser):

    """
    Zeus's option parser
    """

    def __init__(self):
        OptionParser.__init__(self)

    @staticmethod
    def cmd_parser():
        """
        command line parser, parses all of Zeus's arguments and flags
        """
        parser = OptionParser(usage="./zeus.py -d|r|l|f|b DORK|FILE|URL [ATTACKS] [--OPTS]")

        # mandatory options
        mandatory = OptionGroup(parser, "Mandatory Options",
                                "These options have to be used in order for Zeus to run")

        mandatory.add_option("-d", "--dork", dest="dorkToUse", metavar="DORK",
                             help="Specify a singular Google dork to use for queries")

        mandatory.add_option("-l", "--dork-list", dest="dorkFileToUse", metavar="FILE-PATH",
                             help="Specify a file full of dorks to run through")

        mandatory.add_option("-r", "--rand-dork", dest="useRandomDork", action="store_true",
                             help="Use a random dork from the etc/dorks.txt file to perform the scan")

        mandatory.add_option("-b", "--blackwidow", dest="spiderWebSite", metavar="URL",
                             help="Spider a single webpage for all available URL's")

        mandatory.add_option("-f", "--url-file", dest="fileToEnumerate", metavar="FILE-PATH",
                             help="Run an attack on URL's in a given file")

        # being worked on
        # TODO:/
        mandatory.add_option("-u", "--url", dest="singleTargetRecon", metavar="URL",
                             help=SUPPRESS_HELP)

        # attack options
        attacks = OptionGroup(parser, "Attack arguments",
                              "These arguments will give you the choice on how you want to check the websites")

        attacks.add_option("-s", "--sqli", dest="runSqliScan", action="store_true",
                           help="Run a Sqlmap SQLi scan on the discovered URL's")

        attacks.add_option("-p", "--port-scan", dest="runPortScan", action="store_true",
                           help="Run a Nmap port scan on the discovered URL's")

        attacks.add_option("-a", "--admin-panel", dest="adminPanelFinder", action="store_true",
                           help="Search for the websites admin panel")

        attacks.add_option("-x", "--xss-scan", dest="runXssScan", action="store_true",
                           help="Run an XSS scan on the found URL's")

        attacks.add_option("-w", "--whois-lookup", dest="performWhoisLookup", action="store_true",
                           help="Perform a WhoIs lookup on the provided domain")

        attacks.add_option("-c", "--clickjacking", dest="performClickjackingScan", action="store_true",
                           help="Perform a clickjacking scan on a provided URL")

        # being worked on
        # TODO:/
        attacks.add_option("-g", "--github-search", dest="searchGithub", action="store_true",
                           help=SUPPRESS_HELP)

        attacks.add_option("-P", "--pgp", dest="pgpLookup", action="store_true",
                           help="Perform a PGP public key lookup on the found URLs")

        attacks.add_option("--sqlmap-args", dest="sqlmapArguments", metavar="SQLMAP-ARGS",
                           help="Pass the arguments to send to the sqlmap API within quotes & "
                                "separated by a comma. IE 'dbms mysql, verbose 3, level 5'")

        attacks.add_option("--sqlmap-conf", dest="sqlmapConfigFile", metavar="CONFIG-FILE-PATH",
                           help="Pass a configuration file that contains the sqlmap arguments")

        attacks.add_option("--nmap-args", dest="nmapArguments", metavar="NMAP-ARGS",
                           help="Pass the arguments to send to the nmap API within quotes & "
                                "separated by a pipe. IE '-O|-p 445, 1080'")

        attacks.add_option("--show-sqlmap", dest="showSqlmapArguments", action="store_true",
                           help="Show the arguments that the sqlmap API understands")

        attacks.add_option("--show-nmap", dest="showNmapArgs", action="store_true",
                           help="Show the arguments that nmap understands")

        attacks.add_option("--show-possibles", dest="showAllConnections", action="store_true",
                           help="Show all connections made during the admin panel search")

        attacks.add_option("--tamper", dest="tamperXssPayloads", metavar="TAMPER-SCRIPT",
                           help="Send the XSS payloads through tampering before sending to the target")

        # being worked on
        # TODO:/
        attacks.add_option("--thread", dest="threadPanels", action="store_true",
                           help=SUPPRESS_HELP)

        attacks.add_option("--auto", dest="autoStartSqlmap", action="store_true",
                           help="Automatically start the sqlmap API (or at least try to)")

        # search engine options
        engines = OptionGroup(parser, "Search engine arguments",
                              "Arguments to change the search engine used (default is Google)")

        engines.add_option("-D", "--search-engine-ddg", dest="useDDG", action="store_true",
                           help="Use DuckDuckGo as the search engine")

        engines.add_option("-B", "--search-engine-bing", dest="useBing", action="store_true",
                           help="Use Bing as the search engine")

        engines.add_option("-A", "--search-engine-aol", dest="useAOL", action="store_true",
                           help="Use AOL as the search engine")

        # arguments to edit your search patterns
        search_items = OptionGroup(parser, "Search options",
                                   "Arguments that will control the search criteria")

        search_items.add_option("-L", "--links", dest="amountToSearch", type=int, metavar="HOW-MANY-LINKS",
                                help="Specify how many links to try and search on Google")

        search_items.add_option("-M", "--multi", dest="searchMultiplePages", action="store_true",
                                help="Search multiple pages of Google")

        search_items.add_option("-E", "--exclude-none", dest="noExclude", action="store_true",
                                help="Do not exclude URLs because they do not have a GET(query) parameter in them")

        search_items.add_option("-W", "--webcache", dest="parseWebcache", action="store_true",
                                help="Parse webcache URLs for the redirect in them")

        search_items.add_option("--x-forward", dest="forwardedForRandomIP", action="store_true",
                                help="Add a header called 'X-Forwarded-For' with three random IP addresses")

        search_items.add_option("--time-sec", dest="controlTimeout", metavar="SECONDS", type=int,
                                help="Control the sleep and timeout times in relevant situations")

        search_items.add_option("--identify-waf", dest="identifyProtection", action="store_true",
                                help="Attempt to identify if the target is protected by some kind of "
                                     "WAF/IDS/IPS")

        # being worked on
        # TODO:/
        search_items.add_option("--force-ssl", dest="forceSSL", action="store_true",
                                help=SUPPRESS_HELP)

        search_items.add_option("--identify-plugins", dest="identifyPlugin", action="store_true",
                                help="Attempt to identify what plugins the target is using")

        # obfuscation options
        anon = OptionGroup(parser, "Anonymity arguments",
                           "Arguments that help with anonymity and hiding identity")

        anon.add_option("--proxy", dest="proxyConfig", metavar="PROXY-STRING",
                        help="Use a proxy to do the scraping, will not auto configure to the API's")

        anon.add_option("--proxy-file", dest="proxyFileRand", metavar="FILE-PATH",
                        help="Grab a random proxy from a given file of proxies")

        anon.add_option("--random-agent", dest="useRandomAgent", action="store_true",
                        help="Use a random user-agent from the etc/agents.txt file")

        anon.add_option("--agent", dest="usePersonalAgent", metavar="USER-AGENT",
                        help="Use your own personal user-agent"),

        anon.add_option("--tor", dest="useTor", action="store_true",
                        help="Use Tor connection as the proxy and set the firefox browser settings to mimic Tor")

        # miscellaneous options
        misc = OptionGroup(parser, "Misc Options",
                           "These options affect how the program will run")

        misc.add_option("--verbose", dest="runInVerbose", action="store_true",
                        help="Run the application in verbose mode (more output)")

        misc.add_option("--batch", dest="runInBatch", action="store_true",
                        help="Skip the questions and run in default batch mode")

        misc.add_option("--update", dest="updateZeus", action="store_true",
                        help="Update to the latest development version")

        misc.add_option("--hide", dest="hideBanner", action="store_true",
                        help="Hide the banner during running")

        misc.add_option("--version", dest="showCurrentVersion", action="store_true",
                        help="Show the current version and exit")

        # being worked on
        # TODO:/
        misc.add_option("-T", "--x-threads", dest="amountOfThreads", metavar="THREAD-AMOUNT", type=int,
                        help=SUPPRESS_HELP)

        misc.add_option("--show-success", dest="showSuccessRate", action="store_true",
                        help="Calculate the dorks success rate and output the calculation in human readable form")

        misc.add_option("--show-description", dest="showPluginDescription", action="store_true",
                        help="Show the description of the identified plugins")

        parser.add_option_group(mandatory)
        parser.add_option_group(attacks)
        parser.add_option_group(search_items)
        parser.add_option_group(anon)
        parser.add_option_group(engines)
        parser.add_option_group(misc)

        opt, _ = parser.parse_args()
        return opt

    @staticmethod
    def single_show_args(opt):
        """
        parses Zeus's single time run arguments
        """
        if opt.showCurrentVersion:
            print(lib.core.settings.VERSION_STRING)
            exit(0)
        if opt.showSqlmapArguments:
            lib.core.settings.logger.info(lib.core.settings.set_color(
                "there are a total of {} arguments understood by sqlmap API, "
                "they include:".format(len(lib.attacks.sqlmap_scan.sqlmap_opts.SQLMAP_API_OPTIONS))
            ))
            print("\n")
            for arg in lib.attacks.sqlmap_scan.sqlmap_opts.SQLMAP_API_OPTIONS:
                print(
                    "[*] {}".format(arg)
                )
            print("\n")
            lib.core.settings.logger.info(lib.core.settings.set_color(
                "for more information about sqlmap arguments, see here '{}'".format(
                    lib.core.settings.SQLMAP_MAN_PAGE_URL
                )
            ))
            lib.core.common.shutdown()

        if opt.showNmapArgs:
            lib.core.settings.logger.info(lib.core.settings.set_color(
                "there are a total of {} arguments understood by nmap, they include:".format(
                    len(lib.attacks.nmap_scan.nmap_opts.NMAP_API_OPTS)
                )
            ))
            print("\n")
            for arg in lib.attacks.nmap_scan.nmap_opts.NMAP_API_OPTS:
                print(
                    "[*] {}".format(arg)
                )
            print("\n")
            lib.core.settings.logger.info(lib.core.settings.set_color(
                "for more information on what the arguments do please see here '{}'".format(
                    lib.core.settings.NMAP_MAN_PAGE_URL
                )
            ))
            lib.core.common.shutdown()

        # update the program
        if opt.updateZeus:
            lib.core.settings.logger.info(lib.core.settings.set_color(
                "update in progress"
            ))
            lib.core.settings.update_zeus()
            lib.core.common.shutdown()

    @staticmethod
    def verify_args(args=sys.argv):
        not_implemented_args = (
            "-T", "--x-threads", "--force-ssl", "--thread",
            "-g", "--github-search", "-u", "--url"
        )
        # check if any of the arguments are not implemented that have been passed
        # via the command line
        # TODO:/
        # need to create a way to parse all arguments for compatibility with one another
        for arg in args:
            for nia in not_implemented_args:
                if arg == nia:
                    raise lib.core.errors.ZeusArgumentException(
                        "\n\nit appears that one of the arguments you have passed ('{}'), "
                        "has not been implemented into Zeus production yet. This usually means "
                        "that the option is still in testing and is not ready for use. Arguments "
                        "that are still in testing are: {}\n".format(
                            nia, ", ".join(["'{}'".format(a) for a in not_implemented_args])
                        )
                    )