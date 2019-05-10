FROM ubuntu:18.10

WORKDIR /app

RUN apt update && \
	apt install -y \
	libxml2-dev \
	libxslt1-dev \
	libgtk-3-dev \
	libdbus-glib-1-2 \
	python-dev \ 
	python-pip \
	git \
	curl \
	nmap \
	sqlmap \ 
	xvfb \
	&& rm -rf /var/lib/apt/lists/* 

ARG GECKO_DRIVER_VERSION=0.23.0
ARG FIREFOX_VERSION=58.0.2

RUN git clone https://github.com/ekultek/zeus-scanner.git . && \
	pip install -r requirements.txt 

RUN curl -L https://github.com/mozilla/geckodriver/releases/download/v${GECKO_DRIVER_VERSION}/geckodriver-v${GECKO_DRIVER_VERSION}-linux64.tar.gz | tar xz -C /usr/bin 

RUN curl -L https://ftp.mozilla.org/pub/firefox/releases/${FIREFOX_VERSION}/linux-$(uname -m)/en-US/firefox-${FIREFOX_VERSION}.tar.bz2 -o firefox.tar.bz2 && \
	tar xjf firefox.tar.bz2 -C /opt && \
	rm firefox.tar.bz2 && \
	ln -s /opt/firefox/firefox /usr/bin/firefox

CMD ["python", "zeus.py"]

