import re


__product__ = "Moodle"
__description__ = (
    "Moodle is an opensource educational software written in PHP"
)


def search(html, **kwargs):
    html = str(html)
    plugin_detection_schema = (
        re.compile(r".moodle.", re.I),
        re.compile(r".moodlesession.", re.I),
        re.compile(r".php.moodlesession.(\w+)?(\d+)?", re.I)
    )
    for plugin in plugin_detection_schema:
        if plugin.search(html) is not None:
            return True
