import whichcraft
from selenium import webdriver
from selenium.webdriver.common.proxy import *
from selenium.webdriver.remote.errorhandler import WebDriverException

from lib.core.settings import (
    logger,
    set_color
)


class SetBrowser(object):

    """
    set the Firefox browser settings
    """

    def __init__(self, **kwargs):
        self.agent = kwargs.get("agent", None)
        self.proxy = kwargs.get("proxy", None)
        # self.xforward = kwargs.get("xforward", False) # TODO:/
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

    def set_browser(self):
        """
        set up the browser
        """
        profile = webdriver.FirefoxProfile()
        try:
            if not self.tor:
                logger.info(set_color(
                    "setting the browser..."
                ))
                # override the user-agent to be our person one
                profile = profile.set_preference("general.useragent.override", self.agent)
                browser = webdriver.Firefox(profile, proxy=self.__set_proxy())
            else:
                logger.info(set_color(
                    "setting the Tor browser emulation..."
                ))
                profile = self.__tor_browser_emulation(profile)
                browser = webdriver.Firefox(profile)
        except (OSError, WebDriverException):
            if not self.tor:
                profile = profile.set_preference("general.useragent.override", self.agent)
                browser = webdriver.Firefox(profile, proxy=self.__set_proxy(),
                                            executable_path=whichcraft.which("geckodriver"))
            else:
                profile = self.__tor_browser_emulation(profile)
                browser = webdriver.Firefox(profile, executable_path=whichcraft.which("geckodriver"))
        return browser
