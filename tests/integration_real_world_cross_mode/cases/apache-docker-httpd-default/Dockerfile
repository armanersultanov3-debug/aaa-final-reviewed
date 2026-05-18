FROM httpd:2.4-alpine

# The demo httpd.conf is a server-level snippet (Listen / DocumentRoot / etc.)
# that assumes the distribution's LoadModule directives are already present.
# We extract that block from the stock image and prepend it to the demo so
# the snippet stays untouched yet the server actually starts.
RUN grep '^LoadModule' /usr/local/apache2/conf/httpd.conf > /tmp/loadmodules.conf

COPY httpd.conf /tmp/demo.conf
COPY htdocs/ /usr/local/apache2/htdocs/

RUN cat /tmp/loadmodules.conf /tmp/demo.conf > /usr/local/apache2/conf/httpd.conf \
 && rm /tmp/loadmodules.conf /tmp/demo.conf

EXPOSE 80
