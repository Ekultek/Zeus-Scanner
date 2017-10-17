#!/usr/bin/env bash

sudo rm -rf /tmp.x0-lock
sudo apt-get purge --yes --force-yes xvfb
sudo apt-get install --yes --force-yes xvfb