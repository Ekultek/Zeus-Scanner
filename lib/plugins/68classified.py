import re


__product__ = "68-Classifieds-Script"
__description__ = (
    "68 Classifieds Script - Requires PHP"
)


def search(html, **kwargs):
    html = str(html)
    plugin_detection_schema = (
        re.compile(r"http(s)?.//(www.)?68classifieds.com", re.I),
        re.compile(r"68.classifieds.script", re.I),
        re.compile(r"68.classifieds", re.I)
    )
    for plugin in plugin_detection_schema:
        if plugin.search(html) is not None:
            return True
