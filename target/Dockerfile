FROM raesene/bwapp:latest
RUN printf "session.cookie_httponly = 1\n" > /etc/php5/apache2/conf.d/99-hardening.ini
COPY src/ /app/
