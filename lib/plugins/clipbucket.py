import re


__product__ = "ClipBucket"
__description__ = (
    "ClipBucket is an Open Source and freely downloadable PHP "
    "script that will let you start your own Video Sharing website"
)


def search(html, **kwargs):
    html = str(html)
    plugin_detection_schema = (
        re.compile(r"<.\S+.clipbucket", re.I),
        re.compile(r"content.[\'\"]clipbucket", re.I),
        re.compile(r"http(s)?.//(www.)?clip.bucket.com", re.I),
        re.compile(r"http(s)?.//(www.)?clipbucket.com", re.I),
    )
    for plugin in plugin_detection_schema:
        if plugin.search(html) is not None:
            return True
