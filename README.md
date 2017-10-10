[![GitHub issues](https://img.shields.io/github/issues/ekultek/zeus-scanner.svg?style=flat-square)](https://github.com/ekultek/zeus-scanner/issues) 
[![GitHub forks](https://img.shields.io/github/forks/ekultek/zeus-scanner.svg?style=flat-square)](https://github.com/ekultek/zeus-scanner/network) 
[![GitHub license](https://img.shields.io/badge/license-GPL-blue.svg?style=flat-square)](https://raw.githubusercontent.com/ekultek/zeus-scanner/master/LICENSE.md)
[![GitHub stars](https://img.shields.io/github/stars/ekultek/zeus-scanner.svg?style=flat-square)](https://github.com/ekultek/zeus-scanner/stargazers)
[![Twitter](https://img.shields.io/twitter/url/https/github.com/ekultek/zeus-scanner.svg?style=social)](https://twitter.com/intent/tweet?text=Wow:&url=%5Bobject%20Object%5D)

# Zeus-Scanner

### What is Zeus?

Zeus is a advanced dork searching tool that is capable of bypassing search engine API calls, search engine captchas, and IP address blocking from sending many requests to the search engine itself. Zeus can use three different search engines to do the search (_default is Google_). Zeus has a powerful built in engine, automates a hidden web browser to pull the search URL, and can run sqlmap and nmap scans on the URL's.

### Screenshots

Running without a mandatory options, or running the `--help` flag will output Zeus's help menu:
![zeus-help](https://user-images.githubusercontent.com/14183473/30176257-63391c62-93c7-11e7-94d7-68fde7818381.png)
A basic dork scan with the `-d` flag, from the given dork will launch an automated browser and pull the Google page results:
![zeus-dork-scan](https://user-images.githubusercontent.com/14183473/30176252-618b191a-93c7-11e7-84d2-572c12994c4d.png)
Calling the `-s` flag will prompt for you to start the sqlmap API server `python sqlmapapi.py -s` from sqlmap, it will then connect to the API and perform a sqlmap scan on the found URL's.
![zeus-sqlmap-api](https://user-images.githubusercontent.com/14183473/30176259-6657b304-93c7-11e7-81f8-0ed09a6c0268.png)

### Requirements

There are a few requirements for this:

 - Firefox web browser is required as of now, I will be adding the functionality of most web browsers.
 - If you want to run sqlmap through the URL's you will need sqlmap somewhere on your system.
 - If you want to run a port scan using nmap on the URL's IP addresses. You will need nmap on your system.
   - _Highly advised tip_: Add sqlmap and nmap to your ENV PATH
 - Gecko web driver is required and will be installed the first time you run. It will be added to your `/usr/bin` so that it can be run in your ENV PATH.
 - You must be `sudo` for the first time running this so that you can add the driver to your PATH 
 - `selenium-webdriver` package is required to automate the web browser and bypass API calls.
 - `requests` package is required to connect to the URL, and the sqlmap API
 - `python-nmap` package is required to run nmap on the URL's IP addresses
 - `whichcraft` package is required to check if nmap and sqlmap are on your system if you want to use them
 - `pyvirtualdisplay` package is required to hide the browser display while finding the search URL
 - `xvfb` is required by pyvirtualdisplay, it will be installed if not installed on your first run

### Installing

To install Zeus you simply need to do the following:
 
 - **_(optional but highly advised)_** add sqlmap and nmap to your environment PATH by moving them to `/usr/bin` or by adding them to the PATH via terminal
 - Clone the repository `git clone https://github.com/Ekultek/Zeus-Scanner.git`
 - `cd` into zeus-scanner 
 - Run `pip install -r requirements.txt`
 - For your first run, run `sudo python zeus.py`

This will install all the package requirements along with the gecko web driver
