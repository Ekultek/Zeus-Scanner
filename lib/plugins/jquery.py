import re


__product__ = "JQuery"
__description__ = (
    "A fast, concise, JavaScript that simplifies how to traverse "
    "HTML documents, handle events, perform animations, and add AJAX"
)


def search(html, **kwargs):
    html = str(html)
    plugin_detection_schema = (
        re.compile(r"src.[\'\"]?http(s)?.//ajax.googleapis.com.ajax.libs.jquery.\d.\d.\d", re.I),
        re.compile(r".jquery.", re.I),
        re.compile(r"jquery.min.js", re.I)
    )
    for plugin in plugin_detection_schema:
        if plugin.search(html) is not None:
            return True
