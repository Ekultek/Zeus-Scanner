#!/usr/bin/env bash

for pid in $(ps -ef | grep "firefox" | awk '{print $2}'); do kill -9 ${pid}; done > /dev/null 2>&1
mv ~/.mozilla ~/.mozilla.old > /dev/null 2>&1
rm /usr/lib/firefox* > /dev/null 2>&1
sudo apt-get update > /dev/null 2>&1
sudo apt-get --purge --reinstall --assume-yes install firefox=56.0 > /dev/null 2>&1
sudo pip2 install selenium -U > /dev/null 2>&1
