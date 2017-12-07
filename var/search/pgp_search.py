import re

import requests
from bs4 import BeautifulSoup
from requests.exceptions import ReadTimeout

import lib.core.common
import lib.core.settings


def __create_url(ext):
    """
    create the URL with the identifier, usually a hash
    """
    url = lib.core.settings.AUTHORIZED_SEARCH_ENGINES["pgp"]
    items = url.split("/")
    # make sure that there's a `/` in the extension
    if "/" in ext[0]:
        retval = "{}//{}{}".format(items[0], items[2], ext)
    else:
        # otherwise we'll just add it
        retval = "{}//{}/{}".format(items[0], items[2], ext)
    return retval


def __set_headers(**kwargs):
    """
    set the HTTP headers
    """
    agent = kwargs.get("agent", None)
    xforward = kwargs.get("xforward", False)
    if not xforward:
        headers = {
            lib.core.common.HTTP_HEADER.CONNECTION: "close",
            lib.core.common.HTTP_HEADER.USER_AGENT: agent
        }
    else:
        ip_list = (
            lib.core.settings.create_random_ip(),
            lib.core.settings.create_random_ip(),
            lib.core.settings.create_random_ip()
        )
        headers = {
            lib.core.common.HTTP_HEADER.CONNECTION: "close",
            lib.core.common.HTTP_HEADER.USER_AGENT: agent,
            lib.core.common.HTTP_HEADER.X_FORWARDED_FOR: "{}, {}, {}".format(
                ip_list[0], ip_list[1], ip_list[2]
            )
        }
    return headers


def obtain_html(url, query, **kwargs):
    """
    obtain the HTML containing the URL redirects to the public PGP keys
    """
    agent = kwargs.get("agent", None)
    xforward = kwargs.get("xforwad", False)
    proxy = kwargs.get("proxy", None)
    url = url.format(query)
    # regular expression to match if no results are given
    result_regex = re.compile("<.+>no.results.found<.+.>", re.I)
    req = requests.get(
        url,
        params=__set_headers(agent=agent, xforward=xforward),  # set the headers
        proxies=lib.core.settings.proxy_string_to_dict(proxy),
        timeout=10
    )
    status, html = req.status_code, req.content
    if status == 200:
        # check against the regex
        if result_regex.search(str(html)) is not None:
            return None
        else:
            return html
    return None


def gather_urls(html, attribute="a", descriptor="href"):
    """
    get the URLs within the HTML
    """
    redirects, retval = set(), set()
    soup = BeautifulSoup(html, "html.parser")
    for link in soup.findAll(attribute):
        found_redirect = str(link.get(descriptor)).decode("unicode_escape")
        if lib.core.settings.PGP_IDENTIFIER_REGEX.search(found_redirect) is not None:
            redirects.add(found_redirect)
    for link in redirects:
        url = __create_url(link)
        if lib.core.settings.URL_REGEX.match(url):
            retval.add(url)
    return list(retval)


def get_pgp_keys(url_list, query, attribute="pre", **kwargs):
    """
    get the PGP keys by connecting to the URLs and pulling the information from the HTML
    """
    agent = kwargs.get("agent", None)
    proxy = kwargs.get("proxy", None)
    xforward = kwargs.get("xforward", None)
    verbose = kwargs.get("verbose", False)
    amount_to_search = kwargs.get("search_amount", 75)  # TODO:/ add a way to increase this

    data_sep = "-" * 30
    extracted_keys, identifiers = set(), []
    # regex to match the beginning of a PGP key
    identity_matcher = re.compile(r"\bbegin.pgp.public.key.block", re.I)
    amount_left = len(url_list)
    lib.core.settings.logger.info(lib.core.settings.set_color(
        "checking a maximum of {} PGP keys".format(amount_to_search)
    ))
    for i, url in enumerate(url_list, start=1):
        if i >= amount_to_search:
            break
        if verbose:
            lib.core.settings.logger.debug(lib.core.settings.set_color(
                "checking '{}'".format(url), level=10
            ))
        if i % 25 == 0:
            lib.core.settings.logger.info(lib.core.settings.set_color(
                "currently checking PGP key #{}, {} left to check ({} total found)".format(
                    i, amount_to_search - i, amount_left
                )
            ))
        identifiers.append(lib.core.settings.PGP_IDENTIFIER_REGEX.search(str(url)).group())
        try:
            req = requests.get(
                url,
                params=__set_headers(agent=agent, xforward=xforward),
                proxies=lib.core.settings.proxy_string_to_dict(proxy),
                timeout=10
            )
            status, html = req.status_code, req.content
            if status == 200:
                soup = BeautifulSoup(html, "html.parser")
                context = soup.findAll(attribute)[0]
                if identity_matcher.search(str(context)) is not None:
                    extracted_keys.add(context)
        except ReadTimeout:
            lib.core.settings.logger.error(lib.core.settings.set_color(
                "PGP key failed connection, assuming no good and skipping", level=40
            ))
    for i, k in enumerate(extracted_keys):
        pgp_key = str(k).split("<{}>".format(attribute))  # split the string by the tag
        pgp_key = pgp_key[1].split("</{}>".format(attribute))[0]  # split it again by the end tag
        if verbose:
            lib.core.settings.logger.debug(lib.core.settings.set_color(
                "found PGP:", level=10
            ))
            # output the found PGP key if you run in verbose
            print("{}\n{}\n{}".format(data_sep, pgp_key, data_sep))
        lib.core.common.write_to_log_file(
            pgp_key, lib.core.settings.PGP_KEYS_FILE_PATH, lib.core.settings.PGP_KEY_FILENAME.format(identifiers[i], query)
        )


def pgp_main(query, verbose=False):
    try:
        try:
            query = lib.core.settings.replace_http(query, queries=False, complete=True).split(".")[0]
        # make sure the query isn't going to fail
        except Exception:
            query = query
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "searching public PGP files with given query '{}'".format(query)
        ))
        try:
            html = obtain_html(
                lib.core.settings.AUTHORIZED_SEARCH_ENGINES["pgp"], query, agent=lib.core.settings.DEFAULT_USER_AGENT
            )
        except (Exception, ReadTimeout):
            lib.core.settings.logger.warning(lib.core.settings.set_color(
                "connection failed, assuming no PGP keys", level=30
            ))
            html = None
        if html is not None:
            urls = gather_urls(html)
            lib.core.settings.logger.info(lib.core.settings.set_color(
                "found a total of {} URLs".format(len(urls))
            ))
            if verbose:
                lib.core.settings.logger.debug(lib.core.settings.set_color(
                    "found a '{}'".format(urls), level=10
                ))
            lib.core.settings.logger.info(lib.core.settings.set_color(
                "gathering PGP key(s) and writing to a file", level=25
            ))
            return get_pgp_keys(urls, query, verbose=verbose)
        else:
            lib.core.settings.logger.warning(lib.core.settings.set_color(
                "did not find anything using query '{}'".format(query), level=30
            ))
    except KeyboardInterrupt:
        if not lib.core.common.pause():
            lib.core.common.shutdown()