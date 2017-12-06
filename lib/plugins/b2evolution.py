import re


__product__ = "b2evolution"
__description__ = (
    "b2evolution is a powerful blog tool you can install on your own website"
)


def search(html, **kwargs):
    html = str(html)
    plugin_detection_schema = (
        re.compile(r"b2evolution", re.I),
        re.compile(r"powered.by.b\devolution", re.I),
        re.compile(r"powered.by.b\devolution.\d{3}\w+.gif", re.I),
        re.compile(r"http(s)?.//(www.)?b2evolution.net", re.I),
        re.compile(r"visit.b2evolution.s.website", re.I)
    )
    for plugin in plugin_detection_schema:
        if plugin.search(html) is not None:
            return True
