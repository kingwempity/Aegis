FROM php:8.3-cli

WORKDIR /app

COPY . /app

RUN chmod +x /app/init_db.php

EXPOSE 8080

CMD ["php", "-S", "0.0.0.0:8080"]
