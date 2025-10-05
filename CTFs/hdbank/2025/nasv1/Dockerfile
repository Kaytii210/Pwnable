FROM httpd:2.4

RUN useradd -m admin && \
    echo "admin:fakepass" | chpasswd && \
    chsh -s '/bin/bash' admin
RUN useradd -m guest && echo 'guest:guest' | chpasswd && chsh -s '/bin/bash' guest
RUN echo 'HDBH{fake-flag}' > /root/flag.txt && chmod 444 /root/flag.txt

RUN apt-get update -y && \
    apt-get install -y git python3 python3-pip gdb && \
    git clone https://github.com/pwndbg/pwndbg /opt/pwndbg && \
    cd /opt/pwndbg && \
    ./setup.sh

RUN rm -rf /usr/local/apache2/cgi-bin/*

ADD htdocs/ /usr/local/apache2/htdocs/
ADD cgi-bin/controller.cgi /usr/local/apache2/cgi-bin/controller.cgi
ADD httpd.conf /usr/local/apache2/conf

RUN chmod +s /usr/local/apache2/cgi-bin/controller.cgi
