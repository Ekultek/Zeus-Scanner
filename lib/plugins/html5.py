import re


__product__ = "HTML5"
__description__ = (
    "HTML5 is a markup language used for structuring and presenting "
    "content on the World Wide Web. It is the fifth and current major "
    "version of the HTML standard."
)


def search(html, **kwargs):
    html = str(html)
    plugin_detection_schema = (
        re.compile(r".html5.", re.I),
        re.compile(r"\bhtml\d+", re.I)
    )
    for plugin in plugin_detection_schema:
        if plugin.search(html) is not None:
            return True
