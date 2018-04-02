FROM php:7.0-apache

COPY config/php.ini /usr/local/etc/php/php.ini
COPY config/docker-php.conf /etc/apache2/conf-available/docker-php.conf
COPY config/000-default.conf /etc/apache2/sites-available/000-default.conf
COPY src/ /var/www/html/

RUN apt-get update && \
    apt-get upgrade -y && \  
    apt-get clean && \  
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/

RUN mkdir -p /tmp/cache/7badddeddbd076fe8352e80d8ddf3e73/var/www/html/index.php.bin && \
    chown -R www-data:www-data /tmp/cache && \
    chown -R root:root /tmp/cache/7badddeddbd076fe8352e80d8ddf3e73/var/www/html/index.php.bin && \
    chmod 755 /tmp/cache && \
    chmod 000 /tmp/cache/7badddeddbd076fe8352e80d8ddf3e73/var/www/html/index.php.bin && \
    chown -R root:root /var/www/html && \
    chown -R www-data:www-data /var/www/html/sandbox && \
    chmod -R 444 /var/www/html && \
    chmod 755 /var/www/html && \
    chmod 755 /var/www/html/sandbox && \
    chmod 755 /var/www/html/flag && \
    service apache2 restart && \
    chmod 1733 /dev/shm

EXPOSE 80
