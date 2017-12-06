import re


__product__ = "360 Web Manager"
__description__ = (
    "1024 is one of a few CMS's leading the way with the "
    "implementation of the AJAX technology  into all its "
    "areas. This includes dynamic adminstration and user "
    "interaction. 1024 offers you to ability to set up your "
    "own community forums, download area, news posts, member management and more."
)


def search(html, **kwargs):
    html = str(html)
    plugin_detection_schema = (
        re.compile(r"powered.by.360.web.manager", re.I),
        re.compile(r"360webmanager.software", re.I),
        re.compile(r"http(s)?.\S{2}(www.)?360webmanager(.com)?", re.I),
    )
    for plugin in plugin_detection_schema:
        if plugin.search(html) is not None:
            return True
