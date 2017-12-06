import re


__product__ = "4images"
__description__ = (
    "4images is a powerful web-based image gallery "
    "management system. Features include comment system, "
    "user registration and management, password protected "
    "administration area with browser-based upload and HTML "
    "templates for page layout and design."
)


def search(html, **kwargs):
    html = str(html)
    plugin_protection_schema = (
        re.compile(r"http(s)?.//(www.)?4homepages.\w+", re.I),
        re.compile(r"powered.by.<.+>4images<.+.>", re.I),
        re.compile(r"powered.by.4images", re.I)
    )
    for plugin in plugin_protection_schema:
        if plugin.search(html) is not None:
            return True
