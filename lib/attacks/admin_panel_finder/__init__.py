import os
import threading

try:                 # Python 2
    from urllib.request import urlopen
    from urllib.error import HTTPError
except ImportError:  # Python 3
    from urllib2 import urlopen, HTTPError

import requests

import lib.core.common
import lib.core.settings
from var.auto_issue.github import request_issue_creation


def check_for_externals(url, data_sep="-" * 30, **kwargs):
    """
    check if the URL has a robots.txt in it and collect `interesting` information
    out of the page
    """
    robots = kwargs.get("robots", False)
    sitemap = kwargs.get("sitemap", False)
    verbose = kwargs.get("verbose", False)
    batch = kwargs.get("batch", False)

    ext = {
        robots: "/robots.txt",
        sitemap: "/sitemap.xml"
    }
    currently_searching = ext[robots if robots else sitemap]
    if verbose:
        lib.core.settings.logger.debug(lib.core.settings.set_color(
            "currently searching for a '{}'...".format(currently_searching), level=10
        ))
    url = lib.core.settings.replace_http(url)
    full_url = "{}{}{}".format("http://", url, currently_searching)
    conn = requests.get(full_url)
    data = conn.content
    code = conn.status_code
    if code == 404:
        lib.core.settings.logger.error(lib.core.settings.set_color(
            "unable to connect to '{}', assuming does not exist and continuing...".format(
                full_url
            ), level=40
        ))
        return False
    if robots:
        interesting = set()
        for line in data.split("\n"):
            if "Allow" in line:
                interesting.add(line.strip())
        if len(interesting) > 0:
            lib.core.settings.create_tree(full_url, list(interesting))
        else:
            question_msg = "nothing interesting found in robots.txt would you like to display the entire page"
            if not batch:
                to_display = lib.core.common.prompt(
                    question_msg, opts="yN"
                )
            else:
                to_display = lib.core.common.prompt(
                    question_msg, opts="yN", default="n"
                )

            if to_display.lower().startswith("y"):
                print(
                    "{}\n{}\n{}".format(
                        data_sep, data, data_sep
                    )
                )
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "robots.txt page will be saved into a file...", level=25
        ))
        return lib.core.common.write_to_log_file(
            data, lib.core.settings.ROBOTS_PAGE_PATH, lib.core.settings.ROBOTS_TXT_FILENAME.format(
                lib.core.settings.replace_http(url)
            )
        )
    elif sitemap:
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "found a sitemap, saving to file...", level=25
        ))
        return lib.core.common.write_to_log_file(
            data, lib.core.settings.SITEMAP_FILE_LOG_PATH, lib.core.settings.SITEMAP_FILENAME.format(
                lib.core.settings.replace_http(url)
            )
        )


def check_for_admin_page(url, exts, protocol="http://", **kwargs):
    """
    bruteforce the admin page of given URL
    """
    verbose = kwargs.get("verbose", False)
    show_possibles = kwargs.get("show_possibles", False)
    possible_connections, connections = set(), set()
    stripped_url = lib.core.settings.replace_http(str(url).strip())
    for ext in exts:
        # each extension is loaded before this process begins to save time
        # while running this process.
        # it will be loaded and passed instead of loaded during.
        ext = ext.strip()
        true_url = "{}{}{}".format(protocol, stripped_url, ext)
        if verbose:
            lib.core.settings.logger.debug(lib.core.settings.set_color(
                "trying '{}'...".format(true_url), level=10
            ))
        try:
            urlopen(true_url, timeout=5)
            lib.core.settings.logger.info(lib.core.settings.set_color(
                "connected successfully to '{}'...".format(true_url), level=25
            ))
            connections.add(true_url)
        except HTTPError as e:
            data = str(e).split(" ")
            if verbose:
                if "Access Denied" in str(e):
                    lib.core.settings.logger.warning(lib.core.settings.set_color(
                        "got access denied, possible control panel found without external access on '{}'...".format(
                            true_url
                        ),
                        level=30
                    ))
                    possible_connections.add(true_url)
                else:
                    lib.core.settings.logger.error(lib.core.settings.set_color(
                        "failed to connect got error code {}...".format(
                            data[2]
                        ), level=40
                    ))
        except Exception as e:
            if verbose:
                if "<urlopen error timed out>" or "timeout: timed out" in str(e):
                    lib.core.settings.logger.warning(lib.core.settings.set_color(
                        "connection timed out assuming won't connect and skipping...", level=30
                    ))
                else:
                    lib.core.settings.logger.exception(lib.core.settings.set_color(
                        "failed to connect with unexpected error '{}'...".format(str(e)), level=50
                    ))
                    request_issue_creation()
    possible_connections, connections = list(possible_connections), list(connections)
    data_msg = "found {} possible connections(s) and {} successful connection(s)..."
    lib.core.settings.logger.info(lib.core.settings.set_color(
        data_msg.format(len(possible_connections), len(connections))
    ))
    if len(connections) > 0:
        # create the connection tree if we got some connections
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "creating connection tree..."
        ))
        lib.core.settings.create_tree(url, connections)
    else:
        lib.core.settings.logger.fatal(lib.core.settings.set_color(
            "did not receive any successful connections to the admin page of "
            "{}...".format(url), level=50
        ))
    if show_possibles:
        if len(possible_connections) > 0:
            lib.core.settings.logger.info(lib.core.settings.set_color(
                "creating possible connection tree..."
            ))
            lib.core.settings.create_tree(url, possible_connections)
        else:
            lib.core.settings.logger.fatal(lib.core.settings.set_color(
                "did not find any possible connections to {}'s "
                "admin page".format(url), level=50
            ))
    lib.core.settings.logger.warning(lib.core.settings.set_color(
        "only writing successful connections to log file...", level=30
    ))
    if len(connections) > 0:
        lib.core.common.write_to_log_file(
            list(connections), lib.core.settings.ADMIN_PAGE_FILE_PATH, lib.core.settings.ADMIN_PAGE_FILE_PATH.format(
                lib.core.settings.replace_http(url)
            )
        )


def __load_extensions(filename="{}/etc/text_files/link_ext.txt"):
    """
    load the extensions to use from the etc/link_ext file
    """
    # this is where the extensions are loaded from
    with open(filename.format(os.getcwd())) as ext:
        return ext.readlines()


def main(url, show=False, verbose=False, **kwargs):
    """
    main method to be called
    """
    do_threading = kwargs.get("do_threading", False)
    proc_num = kwargs.get("proc_num", 5)
    batch = kwargs.get("batch", False)
    lib.core.settings.logger.info(lib.core.settings.set_color(
        "parsing robots.txt..."
    ))
    results = check_for_externals(url, robots=True, batch=batch)
    if not results:
        lib.core.settings.logger.warning(lib.core.settings.set_color(
            "seems like this page is either blocking access to robots.txt or it does not exist...", level=30
        ))
    lib.core.settings.logger.info(lib.core.settings.set_color(
        "checking for a sitemap..."
    ))
    check_for_externals(url, sitemap=True)
    lib.core.settings.logger.info(lib.core.settings.set_color(
        "loading extensions..."
    ))
    extensions = __load_extensions()
    if verbose:
        lib.core.settings.logger.debug(lib.core.settings.set_color(
            "loaded a total of {} extensions...".format(len(extensions)), level=10
        ))
    lib.core.settings.logger.info(lib.core.settings.set_color(
        "attempting to bruteforce admin panel..."
    ))
    if do_threading:
        lib.core.settings.logger.warning(lib.core.settings.set_color(
            "starting {} threads, you will not be able to end the process until "
            "it is completed...".format(proc_num), level=30
        ))
        tasks = []
        for _ in range(0, proc_num):
            t = threading.Thread(target=check_for_admin_page, args=(url, extensions), kwargs={
                "verbose": verbose,
                "show_possibles": show
            })
            t.daemon = True
            tasks.append(t)
        for thread in tasks:
            thread.start()
            thread.join()
    else:
        check_for_admin_page(url, extensions, show_possibles=show, verbose=verbose)