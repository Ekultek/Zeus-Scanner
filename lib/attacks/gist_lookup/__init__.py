import re
import sys

from bs4 import BeautifulSoup

import lib.core.common
import lib.core.settings


def __create_url(redirect, template="https://gist.github.com{}"):
    """
    create the URL for the Gists
    """
    return template.format(redirect)


def get_raw_html(redirect, verbose=False):
    """
    get the raw HTML of the Gist plus the URL for it
    """
    tag, descriptor = "a", "href"
    raw_gist_regex = re.compile(r".raw.[a-z0-9]{40}", re.I)
    _, status, html, _ = lib.core.common.get_page(redirect)

    if status == 200:
        soup = BeautifulSoup(html, "html.parser")
        for link in soup.findAll(tag):
            raw_gist_redirect = link.get(descriptor)
            if raw_gist_regex.search(str(raw_gist_redirect)) is not None:
                url = __create_url(raw_gist_redirect)
                if verbose:
                    lib.core.settings.logger.debug(lib.core.settings.set_color(
                        "found raw Gist URL '{}'...".format(url), level=10
                    ))
                _, _, html, _ = lib.core.common.get_page(url)
                raw_soup = BeautifulSoup(html, "html.parser")
                return raw_soup, url
    else:
        return None, None


def get_links(page_set, proxy=None, agent=None):
    """
    parse 10 pages of Github gists and use them
    """
    redirects, retval = set(), set()
    gist_search_url = "https://gist.github.com/discover?page={}"
    tag, descriptor = "a", "href"
    gist_regex = re.compile(r"[a-f0-9]{32}", re.I)
    gist_skip_schema = ("stargazers", "forks", "#comments")

    for i in range(page_set):
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "fetching all Gists on page #{}...".format(i+1)
        ))
        _, status, html, _ = lib.core.common.get_page(
            gist_search_url.format(i+1), proxy=proxy, agent=agent
        )
        if status == 200:
            soup = BeautifulSoup(html, "html.parser")
            for link in soup.findAll(tag):
                redirect = link.get(descriptor)
                if not any(s in redirect for s in gist_skip_schema):
                    if gist_regex.search(redirect) is not None:
                        if not any(protocol in redirect for protocol in ["https://", "http://"]):
                            redirects.add(__create_url(redirect))
                        else:
                            redirects.add(redirect)
        else:
            lib.core.settings.logger.warning(lib.core.settings.set_color(
                "page #{} failed to load with status code {} (reason '{}')...".format(
                    i+1, status, lib.core.common.STATUS_CODES[int(status)]
                ), level=30
            ))
            continue
    return redirects


def check_files_for_information(data_to_search, query):
    """
    check the files to see if they contain any of the information that was specified
    """
    # create multiple regex types to ensure that we cover all our
    # bases while we do the searching.
    # this will make it so that if there is a match anywhere
    # in anything, we'll find it.
    data_to_search = str(data_to_search)
    data_regex_schema = (
        # match a URL with or without www
        re.compile(r"(http(s)?)?(.//)?(www.)?{}".format(query), re.I),
        # match our string and any random character around it (I like to call it the tittyex)
        re.compile(r"(.)?{}(.)?".format(query), re.I),
        # single boundary match, checks if it's inside of something else
        re.compile(r"\b{}".format(query), re.I),
        # double boundary, same as above but with another boundary
        re.compile(r"\b{}\b".format(query), re.I),
        # wildcard match
        re.compile(r"{}*".format(query), re.I),
        # normal match
        re.compile(r"{}".format(query), re.I)
    )
    for regex in list(data_regex_schema):
        if regex.search(data_to_search) is not None:
            lib.core.settings.logger.info(lib.core.settings.set_color(
                "found match with given specifics ('{}'), saving Gist to file...".format(
                    regex.pattern
                ), level=25
            ))
            lib.core.common.write_to_log_file(
                data_to_search,
                lib.core.settings.GIST_MATCH_LOG,
                lib.core.settings.GIST_FILENAME.format(query)
            )


# @lib.core.decorators.tail_call_optimized
def github_gist_search_main(query, **kwargs):
    """
    main function for searching Gists
    """
    proxy = kwargs.get("proxy", None)
    agent = kwargs.get("agent", None)
    verbose = kwargs.get("verbose", False)
    page_set = kwargs.get("page_set", 10)

    # there seems to be a recursion issue in this function,
    # so until I get this figured out, we're going to change
    # the maximum recursion of the system when we get here
    sys.setrecursionlimit(1500)

    try:
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "searching a total of {} pages of Gists for '{}'...".format(
                page_set, query
            )
        ))

        if "www." in query:
            query = query.split(".")[1]

        links = get_links(page_set, proxy=proxy, agent=agent)
        if verbose:
            lib.core.settings.logger.debug(lib.core.settings.set_color(
                "found a total of {} links to search...".format(
                    len(links)
                ), level=15
            ))
        for link in list(links):
            if link is not None:
                gist, gist_link = get_raw_html(link, verbose=verbose)
                check_files_for_information(gist, query)
    except KeyboardInterrupt:
        if not lib.core.common.pause():
            lib.core.common.shutdown()
    except Exception as e:
        lib.core.settings.logger.exception(lib.core.settings.set_color(
            "Gist search has failed with error '{}'...".format(str(e)), level=50
        ))