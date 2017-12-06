import re


__product__ = "Atom Feed"
__description__ = (
    "Atom Feeds allow software programs to check for updates published on a website"
)


def search(html, **kwargs):
    html = str(html)
    plugin_detection_schema = (
        re.compile(r"<link.\w+.[\"]?atom.xml[\"]?", re.I),
        re.compile(r"type.[\"]?application.atom.xml[\"]?", re.I),
        re.compile(r"title.[\"]?sitewide.atom.feed[\"]?", re.I)
    )
    for plugin in plugin_detection_schema:
        if plugin.search(html) is not None:
            return True
