import re
import json
import time
import requests

import lib.core.settings
import lib.core.common


def __check_remaining_rate_limit():
    """
    check how many requests you have left to run
    """
    url = lib.core.settings.GITHUB_GIST_SEARCH_URLS["check_rate"]
    data = requests.get(url, params={lib.core.common.HTTP_HEADER.AUTHORIZATION: "token {}".format(
        lib.core.settings.get_token(lib.core.settings.GITHUB_AUTH_PATH)
    )})
    remaining = data.headers["X-RateLimit-Remaining"]
    if int(remaining) == 0:
        lib.core.settings.logger.error(lib.core.settings.set_color(
            "Github only allows 60 unauthenticated requests per hour, you have hit that limit "
            "if you need to do more requests it is recommended to run behind a proxy with a different "
            "user-agent (IE --proxy socks5://127.0.0.1:9050 --random-agent)...", level=40
        ))
        lib.core.settings.shutdown()


def get_raw_data(page_set, proxy=None, agent=None, verbose=False):
    """
    parse 10 pages of Github gists and use them
    """
    retval = set()
    url = lib.core.settings.GITHUB_GIST_SEARCH_URLS["search"]
    headers = {
        lib.core.common.HTTP_HEADER.USER_AGENT: agent,
        lib.core.common.HTTP_HEADER.AUTHORIZATION: "token {}".format(lib.core.settings.get_token(lib.core.settings.GITHUB_AUTH_PATH)),
    }
    lib.core.settings.logger.info(lib.core.settings.set_color(
        "searching a total of {} pages of Gists...".format(page_set[-1])
    ))
    if proxy is not None:
        proxy = lib.core.settings.proxy_string_to_dict(proxy)
    for page in list(page_set):
        data = requests.get(url.format(page), params=headers, proxies=proxy)
        # load the found info into JSON format
        # so we can pull using keys
        data = json.loads(data.content)
        for item in data:
            # get the URL to the raw data so we can search it
            gist_file = item["files"]
            gist_filename = gist_file.keys()
            try:
                if verbose:
                    lib.core.settings.logger.debug(lib.core.settings.set_color(
                        "found filename '{}'...".format(''.join(gist_filename)), level=10
                    ))
                retval.add(gist_file[''.join(gist_filename)]["raw_url"])
            # sometimes the URL doesn't like being pulled, so we'll just skip those ones
            except Exception:
                pass
    return retval


def check_files_for_information(found_url, data_to_search):
    """
    check the files to see if they contain any of the information you specified
    """
    # create a regex to search the data
    data_regex = re.compile(data_to_search, re.I)
    total_found = set()
    try:
        data = requests.get(found_url)
    except requests.exceptions.ConnectionError:
        lib.core.settings.logger.warning(lib.core.settings.set_color(
            "to many requests are being sent to quickly, adding sleep time...", level=30
        ))
        time.sleep(3)
        data = requests.get(found_url)

    if data_regex.search(data.content) is not None:
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "found a match with given specifics, saving full Gist to log file..."
        ))
        total_found.add(found_url)
        lib.core.common.write_to_log_file(
            data.content, lib.core.settings.GIST_MATCH_LOG, "gist-match-{}.log"
        )
    return len(total_found)


def github_gist_search_main(query, **kwargs):
    proxy = kwargs.get("proxy", None)
    agent = kwargs.get("agent", None)
    verbose = kwargs.get("verbose", False)
    thread = kwargs.get("do_threading", False)
    proc_num = kwargs.get("proc_num", 5)
    page_set = kwargs.get("page_set", (1, 2, 3, 4, 5))
    total_found = 0

    if verbose:
        lib.core.settings.logger.debug(lib.core.settings.set_color(
            "checking if you have exceeded your search limit...", level=10
        ))
    __check_remaining_rate_limit()
    lib.core.settings.logger.info(lib.core.settings.set_color(
        "searching Github Gists for '{}'...".format(query)
    ))
    gathered_links = get_raw_data(page_set, proxy=proxy, agent=agent, verbose=verbose)
    lib.core.settings.logger.info(lib.core.settings.set_color(
        "pulled a total of {} URL's to search...".format(len(gathered_links)), level=25
    ))
    if not thread:
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "performing Github Gist search, this will probably take awhile..."
        ))
        for url in gathered_links:
            total = check_files_for_information(url, query)
            total_found += total
    else:
        lib.core.settings.logger.warning(lib.core.settings.set_color(
            "multi-threading is not implemented yet...", level=35
        ))
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "performing Github Gist search, this will probably take awhile..."
        ))
        for url in gathered_links:
            total = check_files_for_information(url, query)
            total_found += total
    if total_found > 0:
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "found a total of {} interesting Gists...".format(total_found)
        ))
    else:
        lib.core.settings.logger.warning(lib.core.settings.set_color(
            "did not find any interesting Gists...", level=30
        ))
