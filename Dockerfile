FROM debian:stretch 

ADD ["sources.list", "/etc/apt/"]

RUN apt update \
    && apt -y  --fix-missing install python3 python3-lxml gcc git make libpcap-dev wget alien net-tools \
    && git clone https://github.com/robertdavidgraham/masscan \
    && cd masscan \
    && make \
    && cd / \
    && wget https://nmap.org/dist/nmap-7.70-1.x86_64.rpm \
    && alien nmap*.rpm \
    && dpkg --install nmap*.deb \
    && apt clean

ADD ["scanservice", "/"]

CMD python3 main.py

