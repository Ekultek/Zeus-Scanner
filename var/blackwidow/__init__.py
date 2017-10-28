import os

import requests
from bs4 import BeautifulSoup

import lib.core.errors
import lib.core.settings


class Blackwidow(object):

    """
    spider to scrape a webpage for all available URL's
    """

    def __init__(self, url, user_agent=None, proxy=None):
        self.url = url
        self.proxy = proxy or None
        self.user_agent = user_agent or lib.core.settings.DEFAULT_USER_AGENT

    @staticmethod
    def get_url_ext(url):
        """
        get the extenstion of the URL
        """
        try:
            data = url.split(".")
            return data[-1] in lib.core.settings.SPIDER_EXT_EXCLUDE
        except Exception:
            pass

    def test_connection(self):
        """
        make sure the connection is good before you continue
        """
        try:
            attempt = requests.get(self.url, params={"user-agent": self.user_agent}, proxies=self.proxy)
            if attempt.status_code == 200:
                return "ok"
            raise lib.core.errors.SpiderTestFailure(
                "failed to connect to '{}', received status code: {}".format(
                    self.url, attempt.status_code
                )
            )
        except Exception as e:
            lib.core.settings.logger.exception(lib.core.settings.set_color(
                "failed to connect to '{}' received error '{}'...".format(
                    self.url, e
                )
            ))

    def scrape_page_for_links(self, given_url, attribute="a", descriptor="href"):
        """
        scrape the webpage's HTML for usable GET links
        """
        unique_links = set()
        true_url = lib.core.settings.replace_http(given_url)
        req = requests.get(given_url, params={"user-agent": self.user_agent}, proxies=self.proxy)
        html_page = req.content
        soup = BeautifulSoup(html_page, "html.parser")
        for link in soup.findAll(attribute):
            found_redirect = link.get(descriptor)
            if found_redirect is not None and lib.core.settings.URL_REGEX.match(found_redirect):
                unique_links.add(found_redirect)
            else:
                unique_links.add("http://{}/{}".format(true_url, found_redirect))
        return list(unique_links)


def blackwidow_main(url, proxy=None, agent=None, verbose=False):
    """
    scrape a given URL for all available links
    """
    lib.core.settings.create_dir("{}/{}".format(os.getcwd(), "log/blackwidow-log"))
    lib.core.settings.logger.info(lib.core.settings.set_color(
        "starting blackwidow on '{}'...".format(url)
    ))
    crawler = Blackwidow(url, user_agent=agent, proxy=proxy)
    if verbose:
        lib.core.settings.logger.debug(lib.core.settings.set_color(
            "testing connection to the URL...", level=10
        ))
    crawler.test_connection()
    if verbose:
        lib.core.settings.logger.debug(lib.core.settings.set_color(
            "connection satisfied, continuing process...", level=10
        ))
    found = crawler.scrape_page_for_links(url)
    file_path = lib.core.settings.write_to_log_file(found, path=lib.core.settings.SPIDER_LOG_PATH, filename="blackwidow-log-{}.log")
    with open(file_path) as data:
        found = data.readlines()
        if len(found) > 0:
            lib.core.settings.logger.info(lib.core.settings.set_color(
                "found a total of {} links from '{}'...".format(
                    len(found), url
                )
            ))
        else:
            lib.core.settings.logger.fatal(lib.core.settings.set_color(
                "did not find any usable links from '{}'...".format(url), level=50
            ))