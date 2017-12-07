import lib.core.common
import lib.core.settings
import var.auto_issue.github


class ClickJackingScanner(object):

    def __init__(self, url):
        self.url = url
        self.safe = lib.core.common.HTTP_HEADER.X_FRAME_OPT
        self.html = open(lib.core.settings.CLICKJACKING_TEST_PAGE_PATH).read()

    def generate_html(self):
        """
        generate the HTML page for the clickjacking, it's up to you
        to put it into play
        """
        return self.html.format(self.url)

    def extract_and_test_headers(self, **kwargs):
        """
        extract the headers from the url given to test if they contain the correct protection
        against clickjacking
        """
        proxy = kwargs.get("proxy", None)
        agent = kwargs.get("agent", None)
        forward = kwargs.get("forward", None)
        if forward is not None:
            ip_addrs = lib.core.settings.create_random_ip()
            headers = {
                lib.core.common.HTTP_HEADER.USER_AGENT: agent,
                lib.core.common.HTTP_HEADER.X_FORWARDED_FOR: "{}, {}, {}".format(
                    ip_addrs[0], ip_addrs[1], ip_addrs[2]
                ),
                lib.core.common.HTTP_HEADER.CONNECTION: "close"
            }
        else:
            headers = {
                lib.core.common.HTTP_HEADER.USER_AGENT: agent,
                lib.core.common.HTTP_HEADER.CONNECTION: "close"
            }
        req, _, _, headers = lib.core.common.get_page(self.url, headers=headers, proxy=proxy)
        headers = req.headers
        if self.safe in headers:
            return False
        return True


def clickjacking_main(url, **kwargs):
    """
    main function for the clickjacking scan
    """
    agent = kwargs.get("agent", None)
    proxy = kwargs.get("proxy", None)
    forward = kwargs.get("forward", None)
    verbose = kwargs.get("verbose", False)
    batch = kwargs.get("batch", False)

    if not batch:
        if lib.core.settings.URL_QUERY_REGEX.match(url):
            question = lib.core.common.prompt(
                "it is recommended to use a URL without a GET(query) parameter, "
                "heuristic testing has detected that the URL provided contains a "
                "GET(query) parameter in it, would you like to continue", opts="yN"
            )
            if question.lower().startswith("n"):
                lib.core.settings.logger.info(lib.core.settings.set_color(
                    "automatically removing all queries from URL"
                ))
                url = "http://{}".format(lib.core.settings.replace_http(url, complete=True))

    scanner = ClickJackingScanner(url)

    if verbose:
        lib.core.settings.logger.debug(lib.core.settings.set_color(
            "generating HTML", level=10
        ))

    data = scanner.generate_html()

    if verbose:
        lib.core.settings.logger.debug(lib.core.settings.set_color(
            "HTML generated successfully", level=10
        ))
        print("{}\n{}\n{}".format("-" * 30, data, "-" * 30))

    try:
        results = scanner.extract_and_test_headers(agent=agent, proxy=proxy, forward=forward)

        if results:
            lib.core.settings.logger.info(lib.core.settings.set_color(
                "it appears that provided URL '{}' is vulnerable to clickjacking, writing "
                "to HTML file".format(url), level=25
            ))
            lib.core.common.write_to_log_file(
                data,
                lib.core.settings.CLICKJACKING_RESULTS_PATH,
                lib.core.settings.CLICKJACKING_FILENAME.format(lib.core.settings.replace_http(url))
            )
        else:
            lib.core.settings.logger.error(lib.core.settings.set_color(
                "provided URL '{}' seems to have the correct protection from clickjacking".format(
                    url
                ), level=40
            ))
    except KeyboardInterrupt:
        if not lib.core.common.pause():
            lib.core.common.shutdown()
    except Exception as e:  # until I figure out the errors, we'll just make issues about them
        lib.core.settings.logger.exception(lib.core.settings.set_color(
            "Zeus failed to process the clickjacking test and received "
            "error code '{}'".format(e), level=50
        ))
        var.auto_issue.github.request_issue_creation()
