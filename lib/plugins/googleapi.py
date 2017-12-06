import re


__product__ = "Google API"
__description__ = (
    "Google APIs is a set of application programming interfaces (APIs) developed by Google "
    "which allow communication with Google Services and their integration to other services"
)


def search(html, **kwargs):
    html = str(html)
    plugin_detection_schema = (
        re.compile(r"src.[\'\"]?http(s)?.//googleapis.com", re.I),
        re.compile(r"src.[\'\"]?http(s)?.//ajax.googleapis.com", re.I),
        re.compile(r".googleapis.", re.I)
    )
    for plugin in plugin_detection_schema:
        if plugin.search(html) is not None:
            return True
