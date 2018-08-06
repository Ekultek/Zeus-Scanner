**_NOTE: due to dumbass people, automatic issue creation has been turned off until further notice_**

----

[![GitHub stars](https://img.shields.io/github/stars/ekultek/zeus-scanner.svg?style=flat-square)](https://github.com/ekultek/zeus-scanner/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/ekultek/zeus-scanner.svg?style=flat-square)](https://github.com/ekultek/zeus-scanner/network) 
[![GitHub issues](https://img.shields.io/github/issues/ekultek/zeus-scanner.svg?style=flat-square)](https://github.com/ekultek/zeus-scanner/issues) 
[![GitHub license](https://img.shields.io/badge/license-GPL-blue.svg?style=flat-square)](https://raw.githubusercontent.com/Ekultek/Zeus-Scanner/master/.github/LICENSE.md)
[![Twitter](https://img.shields.io/twitter/url/https/github.com/ekultek/zeus-scanner.svg?style=social)](https://twitter.com/stay__salty)
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://github.com/Ekultek/Zeus-Scanner#donations)

# Helpful links directory

- [Translations](https://github.com/Ekultek/Zeus-Scanner#translations)
- [What is Zeus](https://github.com/Ekultek/Zeus-Scanner#zeus-scanner)
- [Zeus's features](https://github.com/Ekultek/Zeus-Scanner#features)
- [Requirements and installation](https://github.com/Ekultek/Zeus-Scanner#requirements)
  - [Ubuntu/Debian](https://github.com/Ekultek/Zeus-Scanner#ubuntudebian)
  - [centOS](https://github.com/Ekultek/Zeus-Scanner#centos)
  - [Backbox](https://github.com/Ekultek/Zeus-Scanner#backbox)
  - [other](https://github.com/Ekultek/Zeus-Scanner#others)
- [Screenshots](https://github.com/Ekultek/Zeus-Scanner#screenshots)
- [Demo video](https://vimeo.com/239885768)
- [User manual](https://github.com/Ekultek/Zeus-Scanner/wiki)
  - [How Zeus works](https://github.com/Ekultek/Zeus-Scanner/wiki/How-Zeus-works)
  - [Functionality](https://github.com/Ekultek/Zeus-Scanner/wiki/Functionality)
  - [Passing sqlmap flags with Zeus](https://github.com/Ekultek/Zeus-Scanner/wiki/Passing-flags-to-sqlmap)
- [Legal information](https://github.com/Ekultek/Zeus-Scanner/tree/master/.github)
  - [License (GPL)](https://github.com/Ekultek/Zeus-Scanner/blob/master/.github/LICENSE.md)
  - [Code of conduct](https://github.com/Ekultek/Zeus-Scanner/blob/master/.github/CODE_OF_CONDUCT.md)
- [Report a bug](https://github.com/Ekultek/Zeus-Scanner/issues/new)
- [Open a pull request](https://github.com/Ekultek/Zeus-Scanner/compare)
  - [Contribution guidelines](https://github.com/Ekultek/Zeus-Scanner/blob/master/.github/CONTRIBUTING.md)
- [Donations to Zeus](https://github.com/Ekultek/Zeus-Scanner#donations)
- [Shoutouts](https://github.com/Ekultek/Zeus-Scanner#shoutouts)

# Zeus-Scanner

### What is Zeus?

Zeus is an advanced reconnaissance utility designed to make web application reconnaissance simple. Zeus comes complete with a powerful built-in URL parsing engine, multiple search engine compatibility, the ability to extract URLs from both ban and webcache URLs, the ability to run multiple vulnerability assessments on the target, and is able to bypass search engine captchas. 

### Features

 - A powerful built in URL parsing engine
 - Multiple search engine compatibility (`DuckDuckGo`, `AOL`, `Bing`, and `Google` default is `Google`)
 - Ability to extract the URL from Google's ban URL thus bypassing IP blocks
 - Ability to extract from Google's webcache URL
 - Proxy compatibility (`http`, `https`, `socks4`, `socks5`)
 - Tor proxy compatibility and Tor browser emulation
 - Parse `robots.txt`/`sitemap.xml` and save them to a file
 - Multiple vulnerability assessments (XSS, SQLi, clickjacking, port scanning, admin panel finding, whois lookups, and more)
 - Tamper scripts to obfuscate XSS payloads
 - Can run with a custom default user-agent, one of over 4000 random user-agents, or a personal user-agent
 - Automatic issue creation when an unexpected error arises
 - Ability to crawl a webpage and pull all the links
 - Can run a singular dork, multiple dorks in a given file, or a random dork from a list of over 5000 carefully researched dorks
 - Dork blacklisting when no sites are found with the search query, will save the query to a blacklist file
 - Identify WAF/IPS/IDS protection of over 20 different firewalls
 - Header protection enumeration to check what kind of protection is provided via HTTP headers
 - Saving cookies, headers, and other vital information to log files
 - and much more...

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

##### Basic requirements

 - `libxml2-dev`, `libxslt1-dev`, `python-dev` are required for the installation process
 - Firefox web browser is required as of now, you will need Firefox version `<=58 >=52` (between 52 and 58). Full functionality for other browsers will eventually be added.
 - If you want to run sqlmap through the URL's you will need sqlmap somewhere on your system.
 - If you want to run a port scan using nmap on the URL's IP addresses. You will need nmap on your system.
 - [Geckodriver](https://github.com/mozilla/geckodriver) is required to run the firefox web browser and will be installed the first time you run. It will be added to your `/usr/bin` so that it can be run in your ENV PATH.
 - You must be `sudo` for the first time running this so that you can add the driver to your PATH, you also may need to run as `sudo` depending on your permissions. _NOTE:_ `Depending on permissions you may need to be sudo for any run involving the geckodriver`
 - `xvfb` is required by `pyvirtualdisplay`, it will be installed if not installed on your first run 
 
##### Python package requirements

 - [selenium-webdriver](http://www.seleniumhq.org/projects/webdriver/) package is required to automate the web browser and bypass API calls.
 - [requests](http://docs.python-requests.org/en/master/) package is required to connect to the URL, and the sqlmap API
 - [python-nmap](http://xael.org/pages/python-nmap-en.html) package is required to run nmap on the URL's IP addresses
 - [whichcraft](https://github.com/spookyowl/witchcraft) package is required to check if nmap and sqlmap are on your system if you want to use them
 - [pyvirtualdisplay](https://pyvirtualdisplay.readthedocs.io/en/latest/) package is required to hide the browser display while finding the search URL
 - [lxml](https://lxml.readthedocs.io/en/latest/) is required to parse XML data for the sitemap and save it as such
 - [psutil](https://github.com/giampaolo/psutil) is required to search for running sqlmap API sessions
 - [beautifulsoup](https://www.crummy.com/software/BeautifulSoup/bs4/doc/) is required to pull all the HREF descriptor tags and parse the HTML into an easily workable syntax

### Installation

You can download the latest [tar.gz](https://github.com/ekultek/zeus-scanner/tarball/master), the latest [zip](https://github.com/ekultek/zeus-scanner/zipball/master), or you can find the current stable release [here](https://github.com/Ekultek/Zeus-Scanner/releases/tag/v1.5). Alternatively you can install the latest development version by following the instructions that best match your operating system:

**_NOTE: (optional but highly advised)_** add sqlmap and nmap to your environment PATH by moving them to `/usr/bin` or by adding them to the PATH via terminal

##### Ubuntu/Debian

```
sudo apt-get install libxml2-dev libxslt1-dev python-dev &&  git clone https://github.com/ekultek/zeus-scanner.git && cd zeus-scanner && sudo pip2 install -r requirements.txt && sudo python zeus.py
``` 
 
##### centOS

```
sudo apt-get install gcc python-devel libxml2-dev libxslt1-dev python-dev && git clone https://github.com/ekultek/zeus-scanner.git && cd zeus-scanner && sudo pip2 install -r requirements.txt && sudo python zeus.py
```

#### Backbox

64 bit installation:
```
sudo -s << EOF
aptitude purge firefox
wget https://ftp.mozilla.org/pub/firefox/releases/57.0/linux-x86_64/en-US/firefox-57.0.tar.bz2
tar -xjf firefox-57.0.tar.bz2
rm -rf /opt/firefox*
mv firefox /opt/firefox57
mv /usr/bin/firefox /usr/bin/firefoxold
ln -s /opt/firefox57/firefox-bin /usr/bin/firefox
apt-get install libxml2-dev libxslt1-dev python-dev && git clone https://github.com/ekultek/zeus-scanner.git && cd zeus-scanner && pip2 install -r requirements.txt && python zeus.py
EOF
```

32 bit installation:
```
sudo -s << EOF
aptitude purge firefox
wget https://ftp.mozilla.org/pub/firefox/releases/57.0/linux-i686/en-US/firefox-57.0.tar.bz2
tar -xjf firefox-57.0.tar.bz2
rm -rf /opt/firefox*
mv firefox /opt/firefox57
mv /usr/bin/firefox /usr/bin/firefoxold
ln -s /opt/firefox57/firefox-bin /usr/bin/firefox
apt-get install libxml2-dev libxslt1-dev python-dev && git clone https://github.com/ekultek/zeus-scanner.git && cd zeus-scanner && pip2 install -r requirements.txt && python zeus.py
EOF
```

##### Others

```
sudo apt-get install libxml2-dev libxslt1-dev python-dev && git clone https://github.com/ekultek/zeus-scanner.git && cd zeus-scanner && sudo pip2 install -r requirements.txt && sudo python zeus.py
```

This will install all the package requirements along with the geckodriver


### Donations

Zeus is created by a small team of developers that have an aspiration for information security and a strive to succeed. If you like Zeus and want to donate to our funding, we gladly and appreciatively accept donations via:

 - Bitcoin(BTC): `3DAQGcAQ194NGVs16Mmv75ip45CVuE8cZy`
 - [PayPal](https://www.paypal.me/ZeusScanner)
 - Or you can [Buy us a coffee](https://ko-fi.com/A28355P5)
 
You can be assured that all donations will go towards Zeus funding to make it more reliable and even better, thank you from the Zeus development team

### Shoutouts

##### [OpenSource Projects](https://www.facebook.com/opensourceprojects/)

OpenSource Projects is a Facebook community page who's goal is to give developers, new and old, a easy and simple place to share their opensource contributions and projects. I personally think this is an awesome idea, I know how hard it is to get your code noticed by people and support these guys 100%. Go ahead and give them a like [here](https://www.facebook.com/opensourceprojects/). They will share any opensource project you send them for free. Thank you OpenSource Projects for giving developers a place to share work with one another!


### Translations
 
 - [Spanish](https://github.com/Ekultek/Zeus-Scanner/blob/master/.github/translations/README-spanish.md)
 - [Russian](https://github.com/Ekultek/Zeus-Scanner/blob/master/.github/translations/README-russian.md)
 - [French](https://github.com/Ekultek/Zeus-Scanner/blob/master/.github/translations/README-french.md)
