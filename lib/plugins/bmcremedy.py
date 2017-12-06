import re


__product__ = "BMC Remedy"
__description__ = (
    "BMC Remedy is an IT management ticketing system designed by BMC Software"
)


def search(html, **kwargs):
    html = str(html)
    plugin_detection_schema = (
        re.compile(r"<.+>bmc.\w+.remedy.\w+.mid.\w+.tier.\w+.\d+.\d+...login<.+.>", re.I),
        re.compile(r".bmc.remedy.action.request.system.", re.I),
        re.compile(r"class.[\'\"]?caption[\'\"]?.\W{1,3}\w+..[0-9]{4}.bmc.software[,]?.inc[orporated]?.", re.I)
    )