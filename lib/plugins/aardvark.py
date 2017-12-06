import re


__product__ = "Aardvark-Topsites-PHP"
__description__ = (
    "Aardvark Topsites PHP is a free topsites script built on PHP and MySQL"
)


def search(html, **kwargs):
    html = str(html)
    plugin_detection_schema = (
        re.compile(r"powered.by.aardvark.topsites.php", re.I),
        re.compile(r"aardvark.topsites.php", re.I),
        re.compile(r"http(s)?.//(www.)?aardvarktopsitesphp.com", re.I)
    )
    for plugin in plugin_detection_schema:
        if plugin.search(html) is not None:
            return True
