#!/usr/bin/env bash

for pid in $(ps -ef | grep "firefox" | awk '{print $2}'); do kill -9 ${pid}; done > /dev/null 2>&1