FROM httpd:2.4

RUN apt-get update && apt-get install -y libmariadb-dev libmariadb-dev-compat

RUN rm -rf /usr/local/apache2/cgi-bin/*

ADD htdocs/ /usr/local/apache2/htdocs
ADD cgi-bin/controller.cgi /usr/local/apache2/cgi-bin
ADD httpd.conf /usr/local/apache2/conf

RUN mkdir /usr/local/apache2/htdocs/uploads && \
	chown -R www-data:www-data /usr/local/apache2/htdocs/uploads /usr/local/apache2/cgi-bin

