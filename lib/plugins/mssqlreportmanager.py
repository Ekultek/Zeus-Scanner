import re


__product__ = "Microsoft SQL Report Manager"
__description__ = (
    "Microsoft SQL Server Report Manager - web-based report access and management tool"
)


def search(html, **kwargs):
    html = str(html)
    plugin_detection_schema = (
        re.compile(r"content.[\'\"]?microsoft.sql.server.report", re.I),
        re.compile(r"microsoft.sql.server.report.manager", re.I)
    )
    for plugin in plugin_detection_schema:
        if plugin.search(html) is not None:
            return True
