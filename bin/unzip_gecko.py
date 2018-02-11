import os
import sys
import time
import shlex
import platform
import threading
import subprocess
import tarfile
try:
    import ConfigParser  # python 2
except ImportError:
    import configparser as ConfigParser  # python 3

import whichcraft

import lib.core.common
import lib.core.settings


stop_animation = False
xvfb_path = "{}/etc/scripts/install_xvfb.sh".format(os.getcwd())


def animation(text):
    global stop_animation
    i = 0
    while not stop_animation:
        temp_text = list(text)
        if i >= len(temp_text):
            i = 0
        temp_text[i] = temp_text[i].upper()
        temp_text = ''.join(temp_text)
        sys.stdout.write("\033[92m{}\r\033[0m".format(temp_text))
        sys.stdout.flush()
        i += 1
        time.sleep(0.1)
    else:
        print(text)


def disclaimer():
    question = raw_input(
        "\033[91mAttacking targets without consent is not only illegal, but it "
        "is unethical and frowned upon in most countries. By installing this "
        "program you are agreeing that you are responsible for your own actions, "
        "you are over the age of 18 or legally considered an adult in your "
        "place of origin, and that you will obey all laws, regulations, and "
        "rules set forth by your place of origin. You will only see this disclaimer "
        "once. If you agree to the conditions type 'yes'...\033[0m"
    )
    if question.upper() == "YES":
        return True
    else:
        lib.core.settings.logger.fatal(lib.core.settings.set_color(
            "you have not agreed with the terms of service, so "
            "Zeus will shut down now", level=50
        ))
        return False


def parse_hosts(filepath="/etc/hosts"):
    to_append = "127.0.0.1\tlocalhost"
    appened = False
    with open(filepath, "a+") as etc:
        for line in etc:
            if line.strip() == to_append:
                appened = True
        if not appened:
            etc.seek(0)
            etc.write(to_append + "\n")


def find_tools(to_search=("sqlmap", "nmap"), directory="{}/bin/paths", filename="path_config.ini"):
    global stop_animation

    lib.core.settings.create_dir(directory.format(os.getcwd()))
    full_path = "{}/{}".format(
        directory.format(os.getcwd()),
        filename
    )
    cfgfile = open(full_path, "a+")
    parser = ConfigParser.ConfigParser()
    path_schema = {}
    for item in to_search:
        path_obj = whichcraft.which(item)
        if path_obj is not None:
            path_schema[item] = path_obj
        else:
            path_schema[item] = None
    for key, value in path_schema.iteritems():
        if value is None:
            stop_animation = True
            provided_path = lib.core.common.prompt(
                "what is the full path to {} on your system".format(key)
            )
            path_schema[key] = provided_path
    for program, path in path_schema.iteritems():
        parser.add_section(program)
        parser.set(program, "path", path)
    parser.write(cfgfile)
    cfgfile.close()


def config_gecko_version(browser_version):
    """
    figure out which gecko version you need
    """
    version_specs = {
        (57, 58): 19,
        (56, 55, 54): 18,
        (53, 52): 17
    }
    if isinstance(browser_version, (tuple, list, set)):
        major = browser_version[0]
        for key in version_specs.keys():
            for num in key:
                if num == major:
                    return version_specs[key]
    else:
        if "." in browser_version:
            major = browser_version.split(".")[0]
        else:
            major = browser_version
        for key in version_specs.keys():
            for num in key:
                if num == int(major):
                    return version_specs[key]


def check_os(current=platform.platform()):
    """
    check the users operating system..
    """
    if "linux" in str(current).lower():
        return True
    return False


def check_xvfb(exc="Xvfb"):
    """
    test for xvfb on the users system
    """
    global xvfb_path
    global stop_animation

    if whichcraft.which(exc) is None:
        cmd = shlex.split("sudo sh {}".format(xvfb_path))
        subprocess.call(cmd)
        stop_animation = True

    else:
        return True


def check_if_run(file_check="{}/bin/executed.txt"):
    """
    check if the application has been run before by reading the executed.txt file
    """
    if os.path.isfile(file_check.format(os.getcwd())):
        with open(file_check.format(os.getcwd())) as exc:
            if "FALSE" in exc.read():
                return True
            return False
    else:
        with open(file_check.format(os.getcwd()), "a+") as exc:
            exc.write("FALSE")
            return True


def untar_gecko(filename="{}/bin/drivers/geckodriver-v0.{}.0-linux{}.tar.gz", verbose=False):
    """
    untar the correct gecko driver for your computer architecture
    """
    global stop_animation

    arch_info = {"64bit": "64", "32bit": "32"}
    file_arch = arch_info[platform.architecture()[0]]
    ff_version = lib.core.settings.get_browser_version(output=False)
    if isinstance(ff_version, str) or ff_version is None:
        stop_animation = True
        ff_version = lib.core.common.prompt(
            "enter your firefox browser version (if you don't know it run firefox --version)"
        )
    gecko_version = config_gecko_version(ff_version)
    if gecko_version is None:
        stop_animation = True
        lib.core.settings.logger.fatal(lib.core.settings.set_color(
            "your current firefox version is not supported by Zeus", level=50
        ))
        lib.core.common.shutdown()
    gecko_full_filename = filename.format(os.getcwd(), gecko_version, file_arch)
    with open(lib.core.settings.GECKO_VERSION_INFO_PATH, "a+") as log:
        log.write(gecko_full_filename.split("/")[-1])
    tar = tarfile.open(filename.format(os.getcwd(), gecko_version, file_arch), "r:gz")
    try:
        tar.extractall("/usr/bin")
    except IOError as e:
        if "Text file busy" in str(e):
            tar.close()
            pass
    except Exception as e:
        if "[Errno 13] Permission denied: '/usr/bin/geckodriver'" in str(e):
            lib.core.settings.logger.exception(lib.core.settings.set_color(
                "first run must be ran as root (sudo python zeus.py)", level=50
            ))
        else:
            lib.core.settings.logger.exception(lib.core.settings.set_color(
                "ran into exception '{}', logged to current log file".format(e), level=50
            ))
        exit(-1)
    tar.close()


def ensure_placed(item="geckodriver", verbose=False):
    """
    use whichcraft to ensure that the driver has been placed in your PATH variable
    """
    if not whichcraft.which(item):
        lib.core.settings.logger.fatal(lib.core.settings.set_color(
            "the executable '{}' does not appear to be in your /usr/bin PATH. "
            "please untar the correct geckodriver (if not already done) and move "
            "it to /usr/bin.".format(item), level=50
        ))
        exit(-1)
    else:
        return True


def main(rewrite="{}/bin/executed.txt", verbose=False):
    """
    main method
    """
    if not check_os():
        raise NotImplementedError(lib.core.settings.set_color(
            "as of now, Zeus requires Linux to run successfully "
            "your current operating system '{}' is not implemented "
            "yet".format(platform.platform()), level=50
        ))
    if check_if_run():
        if not disclaimer():
            exit(1)
        t = threading.Thread(target=animation, args=(
            "seems this is your first time running the application, doing setup please wait..",))
        t.daemon = True
        t.start()
        find_tools()
        check_xvfb()
        untar_gecko(verbose=verbose)
        parse_hosts()
        if ensure_placed(verbose=verbose):
            with open(rewrite.format(os.getcwd()), "w") as rw:
                rw.write("TRUE")
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "done, continuing process"
        ))
    else:
        pass
