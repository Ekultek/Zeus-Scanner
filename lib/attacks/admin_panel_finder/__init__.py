import os

try:                 # Python 2
    from urllib.request import urlopen
    from urllib.error import HTTPError
except ImportError:  # Python 3
    from urllib2 import urlopen, HTTPError

from var.auto_issue.github import request_issue_creation
from lib.settings import (
    logger,
    replace_http,
    set_color,
    create_tree,
)


def check_for_admin_page(url, exts, protocol="http://", show_possibles=False, verbose=False):
    possible_connections, connections = set(), set()
    stripped_url = replace_http(url.strip())
    for ext in exts:
        ext = ext.strip()
        true_url = "{}{}{}".format(protocol, stripped_url, ext)
        if verbose:
            logger.debug(set_color(
                "trying '{}'...".format(true_url), level=10
            ))
        try:
            urlopen(true_url, timeout=5)
            logger.info(set_color(
                "connected successfully to '{}'...".format(true_url)
            ))
            connections.add(true_url)
        except HTTPError as e:
            data = str(e).split(" ")
            if verbose:
                if "Access Denied" in str(e):
                    logger.warning(set_color(
                        "got access denied, possible control panel found without external access on '{}'...".format(
                            true_url
                        ),
                        level=30
                    ))
                    possible_connections.add(true_url)
                else:
                    logger.error(set_color(
                        "failed to connect got error code {}...".format(
                            data[2]
                        ), level=40
                    ))
        except Exception as e:
            if verbose:
                if "<urlopen error timed out>" or "timeout: timed out" in str(e):
                    logger.warning(set_color(
                        "connection timed out after five seconds "
                        "assuming won't connect and skipping...", level=30
                    ))
                else:
                    logger.exception(set_color(
                        "failed to connect with unexpected error '{}'...".format(str(e)), level=50
                    ))
                    request_issue_creation()
    possible_connections, connections = list(possible_connections), list(connections)
    data_msg = "found {} possible connections(s) and {} successful connection(s)..."
    logger.info(set_color(
        data_msg.format(len(possible_connections), len(connections))
    ))
    if len(connections) != 0:
        logger.info(set_color(
            "creating connection tree..."
        ))
        create_tree(url, connections)
    else:
        logger.fatal(set_color(
            "did not find any successful connections to {}'s "
            "admin page", level=50
        ))
    if show_possibles:
        if len(possible_connections) != 0:
            logger.info(set_color(
                "creating possible connection tree..."
            ))
            create_tree(url, possible_connections)
        else:
            logger.fatal(set_color(
                "did not find any possible connections to {}'s "
                "admin page", level=50
            ))


def __load_extensions(filename="{}/etc/link_ext.txt"):
    with open(filename.format(os.getcwd())) as ext:
        return ext.readlines()


def main(url, show=False, verbose=False):
    logger.info(set_color(
        "loading extensions..."
    ))
    extensions = __load_extensions()
    if verbose:
        logger.debug(set_color(
            "loaded a total of {} extensions...".format(len(extensions)), level=10
        ))
    logger.info(set_color(
        "attempting to bruteforce admin panel..."
    ))
    check_for_admin_page(url, extensions, show_possibles=show, verbose=verbose)
