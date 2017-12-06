import re


__product__ = "RSS Feed"
__description__ = (
    "RSS (Rich Site Summary) is a type of web feed which allows "
    "users to access updates to online content in a standardized, "
    "computer-readable format"
)


def search(html, **kwargs):
    html = str(html)
    plugin_detection_schema = (
        re.compile(r"type.[\'\"]?application/rss.xml[\'\"]?", re.I),
        re.compile(r"title.[\'\"]?rss.feed[\'\"]?", re.I)
    )
    for plugin in plugin_detection_schema:
        if plugin.search(html) is not None:
            return True
