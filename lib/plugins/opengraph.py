import re


__product__ = "Open-Graph-Protocol"
__description__ = (
    "The Open Graph protocol enables you to integrate "
    "your Web pages into the social graph. It is currently "
    "designed for Web pages representing profiles of real-world "
    "things. Things like movies, sports teams, celebrities, "
    "and restaurants. Including Open Graph tags on your Web page, "
    "makes your page equivalent to a Facebook Page"
)


def search(html, **kwargs):
    html = str(html)
    plugin_detection_schema = (
        re.compile(r".og.title.", re.I),
        re.compile(".fb.admins.", re.I),
        re.compile(r".og.type.", re.I),
        re.compile(r".fb.app.id.", re.I)
    )
    for plugin in plugin_detection_schema:
        if plugin.search(html) is not None:
            return True
