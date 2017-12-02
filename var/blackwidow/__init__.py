import os
import sys
reload(sys)
sys.setdefaultencoding("utf-8")  # this will take care of most of the Unicode errors.

from bs4 import BeautifulSoup

import lib.core.errors
import lib.core.common
import lib.core.settings
import var.auto_issue.github


class Blackwidow(object):

    """
    spider to scrape a webpage for all available URL's
    """

    def __init__(self, url, user_agent=None, proxy=None, forward=None):
        self.url = url
        self.forward = forward or None
        self.proxy = lib.core.settings.proxy_string_to_dict(proxy) or None
        self.user_agent = user_agent or lib.core.settings.DEFAULT_USER_AGENT

    @staticmethod
    def get_url_ext(url):
        """
        get the extension of the URL
        """
        try:
            data = url.split(".")
            return data[-1] in lib.core.settings.SPIDER_EXT_EXCLUDE
        except (IndexError, Exception):
            pass

    def test_connection(self):
        """
        make sure the connection is good before you continue
        """
        try:
            # verify=False will take care of SSLErrors
            attempt, status, _, _ = lib.core.common.get_page(
                self.url, agent=self.user_agent, xforward=self.forward, skip_verf=True,
                proxy=self.proxy
            )
            if status == 200:
                return "ok", None
            return "fail", attempt.status_code
        except Exception as e:
            if "Max retries exceeded with url" in str(e):
                info_msg = ""
                if "https://" in self.url:
                    info_msg += ", try dropping https:// to http://"
                else:
                    info_msg += ""
                lib.core.settings.logger.fatal(lib.core.settings.set_color(
                    "provided website '{}' is refusing connection{}...".format(
                        self.url, info_msg
                    ), level=50
                ))
                lib.core.common.shutdown()
            else:
                lib.core.settings.logger.exception(lib.core.settings.set_color(
                    "failed to connect to '{}' received error '{}'...".format(
                        self.url, e
                    ), level=50
                ))
                var.auto_issue.github.request_issue_creation()
                lib.core.common.shutdown()

    def scrape_page_for_links(self, given_url, attribute="a", descriptor="href"):
        """
        scrape the webpage's HTML for usable GET links
        """
        unique_links = set()
        true_url = lib.core.settings.replace_http(given_url)
        _, status, html_page, _ = lib.core.common.get_page(
            given_url, agent=self.user_agent, proxy=self.proxy
        )
        soup = BeautifulSoup(html_page, "html.parser")
        for link in soup.findAll(attribute):
            found_redirect = str(link.get(descriptor)).decode("unicode_escape")
            if found_redirect is not None and lib.core.settings.URL_REGEX.match(found_redirect):
                unique_links.add(found_redirect)
            else:
                unique_links.add("http://{}/{}".format(true_url, found_redirect))
        return list(unique_links)


def blackwidow_main(url, **kwargs):
    """
    scrape a given URL for all available links
    """
    verbose = kwargs.get("verbose", False)
    proxy = kwargs.get("proxy", None)
    agent = kwargs.get("agent", None)
    forward = kwargs.get("forward", None)

    if forward is not None:
        forward = (
            lib.core.settings.create_random_ip(),
            lib.core.settings.create_random_ip(),
            lib.core.settings.create_random_ip()
        )

    if verbose:
        lib.core.settings.logger.debug(lib.core.settings.set_color(
            "settings user-agent to '{}'...".format(agent), level=10
        ))
    if proxy is not None:
        if verbose:
            lib.core.settings.logger.debug(lib.core.settings.set_color(
                "running behind proxy '{}'...".format(proxy), level=10
            ))
    lib.core.settings.create_dir("{}/{}".format(os.getcwd(), "log/blackwidow-log"))
    lib.core.settings.logger.info(lib.core.settings.set_color(
        "starting blackwidow on '{}'...".format(url)
    ))
    crawler = Blackwidow(url, user_agent=agent, proxy=proxy, forward=forward)
    if verbose:
        lib.core.settings.logger.debug(lib.core.settings.set_color(
            "testing connection to the URL...", level=10
        ))
    test_code = crawler.test_connection()
    if not test_code[0] == "ok":
        error_msg = (
            "connection test failed with status code: {}, reason: '{}'. "
            "test connection needs to pass, try a different link..."
        )
        for error_code in lib.core.common.STATUS_CODES.keys():
            if error_code == test_code[1]:
                lib.core.settings.logger.fatal(lib.core.settings.set_color(
                    error_msg.format(
                        test_code[1], lib.core.common.STATUS_CODES[error_code].title()
                    ), level=50
                ))
                lib.core.common.shutdown()
        lib.core.settings.logger.fatal(lib.core.settings.set_color(
            error_msg.format(
                test_code[1], lib.core.common.STATUS_CODES["other"].title()
            ), level=50
        ))
        lib.core.common.shutdown()
    else:
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "connection test succeeded, continuing...", level=25
        ))
    lib.core.settings.logger.info(lib.core.settings.set_color(
        "crawling given URL '{}' for links...".format(url)
    ))
    found = crawler.scrape_page_for_links(url)
    if len(found) > 0:
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "found a total of {} links from given URL '{}'...".format(
                len(found), url
            ), level=25
        ))
        lib.core.common.write_to_log_file(found, path=lib.core.settings.SPIDER_LOG_PATH,
                                          filename=lib.core.settings.BLACKWIDOW_FILENAME)
    else:
        lib.core.settings.logger.fatal(lib.core.settings.set_color(
            "did not find any usable links from '{}'...".format(url), level=50
        ))