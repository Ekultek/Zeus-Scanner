import re


__product__ = "3COM-NBX"
__description__ = (
    "3COM NBX phone system. The NBX NetSet utility is a web "
    "interface in which you configure and manage the NBX "
    "system. NBX systems present the NBX NetSet utility "
    "through an embedded web server that is integrated in system software."
)


def search(html, **kwargs):
    html = str(html)
    plugin_detection_schema = (
        re.compile(r"nbx.netset", re.I),
        re.compile(r"<.+>nbx.netset<.+.>", re.I),
        re.compile(r"3com.corporation", re.I),
        re.compile(r"nbx.corporation", re.I),
        re.compile(r"http(s)?.//(www.)?nbxhelpdesk.com", re.I),
        re.compile(r"nbx.help.desk", re.I)
    )
    for plugin in plugin_detection_schema:
        if plugin.search(html) is not None:
            return True
