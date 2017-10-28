[![GitHub stars](https://img.shields.io/github/stars/ekultek/zeus-scanner.svg?style=flat-square)](https://github.com/ekultek/zeus-scanner/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/ekultek/zeus-scanner.svg?style=flat-square)](https://github.com/ekultek/zeus-scanner/network) 
[![GitHub issues](https://img.shields.io/github/issues/ekultek/zeus-scanner.svg?style=flat-square)](https://github.com/ekultek/zeus-scanner/issues) 
[![GitHub license](https://img.shields.io/badge/license-GPL-blue.svg?style=flat-square)](https://raw.githubusercontent.com/Ekultek/Zeus-Scanner/master/.github/LICENSE.md)
[![Twitter](https://img.shields.io/twitter/url/https/github.com/ekultek/zeus-scanner.svg?style=social)](https://twitter.com/Zeus_Scanner)
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://github.com/Ekultek/Zeus-Scanner#donations)
# Helpful links directory

- [Overview](https://github.com/Ekultek/Zeus-Scanner#zeus-scanner)
- [Report a bug](https://github.com/Ekultek/Zeus-Scanner/issues/new)
- [Open a pull request](https://github.com/Ekultek/Zeus-Scanner/compare)
- [Requirements and installation](https://github.com/Ekultek/Zeus-Scanner#requirements)
- [Screenshots](https://github.com/Ekultek/Zeus-Scanner#screenshots)
- [Demo video](https://vimeo.com/239885768)
- [User manual](https://github.com/Ekultek/Zeus-Scanner/wiki/Functionality)
  - [How it works](https://github.com/Ekultek/Zeus-Scanner/wiki/How-Zeus-works)
  - [Functionality](https://github.com/Ekultek/Zeus-Scanner/wiki/Functionality)
  - [How to use sqlmap with Zeus](https://github.com/Ekultek/Zeus-Scanner/wiki/Passing-flags-to-sqlmap)
- [Legal information](https://github.com/Ekultek/Zeus-Scanner/tree/master/.github)
  - [License](https://github.com/Ekultek/Zeus-Scanner/blob/master/.github/LICENSE.md)
  - [Code of conduct](https://github.com/Ekultek/Zeus-Scanner/blob/master/.github/CODE_OF_CONDUCT.md)
  - [Contributing](https://github.com/Ekultek/Zeus-Scanner/blob/master/.github/CONTRIBUTING.md)
- [Donations to Zeus](https://github.com/Ekultek/Zeus-Scanner#donations)

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

You can see more screenshots [here](https://github.com/Ekultek/Zeus-Scanner/wiki/Screenshots)

### Demo

[![to_video](https://user-images.githubusercontent.com/14183473/31474224-feb8c022-aebe-11e7-9684-1ba83f4fd7ff.png)
](https://vimeo.com/239885768)

### Requirements

There are some requirements for this to be run successfully.

 - You may need to run `sudo apt-get install libxml2-dev libxslt1-dev python-dev`
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
 - `lxml` is required to parse XML data for the sitemap and save it as such
 - `google-api-python-client` is required to search via Google's API client
 - `psutil` is required to search for running sqlmap API sessions
 - `httplib2` is required to allow user-agent changes during Google's API client searches
 - `beautifulsoup` is required to pull all the HREF descriptor tags while using the blackwidow crawler

### Installing

You download the latest zip/tarball [here](https://github.com/Ekultek/Zeus-Scanner/releases/tag/v1.1) or follow the following steps here:
 
 - **_(optional but highly advised)_** add sqlmap and nmap to your environment PATH by moving them to `/usr/bin` or by adding them to the PATH via terminal
 - You made need to run `sudo apt-get install libxml2-dev libxslt1-dev python-dev`
 - Clone the repository `git clone https://github.com/Ekultek/Zeus-Scanner.git`
 - `cd` into zeus-scanner 
 - Run `pip install -r requirements.txt`
 - For your first run, run `sudo python zeus.py`

This will install all the package requirements along with the gecko web driver


### Donations

Zeus is created by a small team of developers that have an aspiration for information security and a strive to succeed. If you like Zeus and want to donate to our funding, we gladly and appreciatively accept donations via:

 - Bitcoin(BTC) via: `3DAQGcAQ194NGVs16Mmv75ip45CVuE8cZy`
 - [PayPal](https://www.paypal.me/ZeusScanner)
 - Or you can [Buy me a coffee](https://ko-fi.com/A28355P5)
 
You can be assured that all donations will go towards Zeus funding to make it more reliable and even better, thank you from the Zeus development team