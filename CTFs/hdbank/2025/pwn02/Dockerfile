FROM ubuntu:24.04

RUN apt-get update && apt-get install -y libssl3 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY chall .
COPY flag.txt

RUN mkdir -p uploads

RUN chmod +x chall
CMD ["./chall"]
