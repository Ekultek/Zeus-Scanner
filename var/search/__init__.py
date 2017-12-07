import whichcraft
from selenium import webdriver
from selenium.webdriver.common.proxy import *
from selenium.webdriver.remote.errorhandler import WebDriverException

from lib.core.common import HTTP_HEADER
from lib.core.settings import (
    logger,
    set_color,
    create_random_ip,
    DEFAULT_USER_AGENT
)


class SetBrowser(object):

    """
    set the Firefox browser settings
    """

    def __init__(self, **kwargs):
        self.agent = kwargs.get("agent", DEFAULT_USER_AGENT)
        self.proxy = kwargs.get("proxy", None)
        self.xforward = kwargs.get("xforward", False)
        self.tor = kwargs.get("tor", False)
        self.tor_port = kwargs.get("port", 9050)

    def __set_proxy(self):
        """
        set the browser proxy settings
        """
        if not self.tor and self.proxy is not None:
            proxy_type = self.proxy.keys()
            proxy_to_use = Proxy({
                "proxyType": ProxyType.MANUAL,
                "httpProxy": self.proxy[proxy_type[0]],
                "ftpProxy": self.proxy[proxy_type[0]],
                "sslProxy": self.proxy[proxy_type[0]],
                "noProxy": ""
            })
            return proxy_to_use
        else:
            return None

    def __tor_browser_emulation(self, ff_browser):
        """
        set the Firefox browser settings to mimic the Tor browser
        """
        preferences = {
            "privacy": [
                # set the privacy settings
                ("places.history.enabled", False),
                ("privacy.clearOnShutdown.offlineApps", True),
                ("privacy.clearOnShutdown.passwords", True),
                ("privacy.clearOnShutdown.siteSettings", True),
                ("privacy.sanitize.sanitizeOnShutdown", True),
                ("signon.rememberSignons", False),
                ("network.cookie.lifetimePolicy", 2),
                ("network.dns.disablePrefetch", True),
                ("network.http.sendRefererHeader", 0)
            ],
            "proxy": [
                # set the proxy settings
                ("network.proxy.type", 1),
                ("network.proxy.socks_version", 5),
                ("network.proxy.socks", '127.0.0.1'),
                ("network.proxy.socks_port", self.tor_port),
                ("network.proxy.socks_remote_dns", True)
            ],
            "javascript": [
                # disabled the javascript settings
                ("javascript.enabled", False)
            ],
            "download": [
                # get a speed increase by not downloading the images
                ("permissions.default.image", 2)
            ],
            "user-agent": [
                # set the user agent settings
                ("general.useragent.override", self.agent)
            ]
        }
        for preference in preferences.iterkeys():
            for setting in preferences[preference]:
                ff_browser.set_preference(setting[0], setting[1])
        return ff_browser

    def __set_x_forward(self, profile):
        """
        set the X-Forwarded-For headers for selenium, this can only be done
        if you are using a profile for Firefox, and ONLY IN FIREFOX.
        """
        ip_list = (
            create_random_ip(),
            create_random_ip(),
            create_random_ip()
        )
        # references:
        # https://eveningsamurai.wordpress.com/2013/11/21/changing-http-headers-for-a-selenium-webdriver-request/
        # https://stackoverflow.com/questions/6478672/how-to-send-an-http-requestheader-using-selenium-2/22238398#22238398
        # https://blog.giantgeek.com/?p=1455

        # amount of headers to modify
        profile.set_preference("modifyheaders.headers.count", 1)
        # action to take on the headers
        profile.set_preference("modifyheaders.headers.action0", "Add")
        # header name, in this case it's `X-Forwarded-For`
        profile.set_preference("modifyheaders.headers.name0", HTTP_HEADER.X_FORWARDED_FOR)
        # header value, in this case, it's 3 random IP addresses
        profile.set_preference("modifyheaders.headers.value0", "{}, {}, {}".format(
            ip_list[0], ip_list[1], ip_list[2]
        ))
        # enable the header modification
        profile.set_preference("modifyheaders.headers.enabled0", True)
        # send it through the configuration
        profile.set_preference("modifyheaders.config.active", True)
        # turn it on from the new configuration
        profile.set_preference("modifyheaders.config.alwaysOn", True)
        # as always, change the user agent
        profile.set_preference("general.useragent.override", self.agent)
        return profile

    def set_browser(self):
        """
        set the browser settings
        """
        profile = webdriver.FirefoxProfile()
        try:
            if not self.tor:
                logger.info(set_color(
                    "setting the browser"
                ))
                profile.set_preference("general.useragent.override", self.agent)
                browser = webdriver.Firefox(profile, proxy=self.__set_proxy())
            elif self.xforward:
                profile = self.__set_x_forward(profile)
                browser = webdriver.Firefox(profile, proxy=self.__set_proxy())
            else:
                logger.info(set_color(
                    "setting the Tor browser emulation"
                ))
                profile = self.__tor_browser_emulation(profile)
                browser = webdriver.Firefox(profile)
        except (OSError, WebDriverException):
            if not self.tor:
                profile.set_preference("general.useragent.override", self.agent)
                browser = webdriver.Firefox(profile, proxy=self.__set_proxy(),
                                            executable_path=whichcraft.which("geckodriver"))
            elif self.xforward:
                profile = self.__set_x_forward(profile)
                browser = webdriver.Firefox(profile, proxy=self.__set_proxy())
            else:
                profile = self.__tor_browser_emulation(profile)
                browser = webdriver.Firefox(profile, executable_path=whichcraft.which("geckodriver"))
        return browser
