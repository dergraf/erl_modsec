FROM ubuntu:latest as base

RUN apt-get update -y \
    && apt-get upgrade -y \
    && apt-get install -y \
        libmodsecurity-dev \
        build-essential \
        curl git \
        erlang \
    && git clone https://github.com/coreruleset/coreruleset \
    && cd coreruleset \
    && git checkout v3.3/dev \
    && cp -r rules / \
    && cp crs-setup.conf.example /01_crs-setup.conf \
    && cd .. \
    && rm -rf coreruleset/ \
    && apt-get -y autoremove \
    && apt-get -y autoclean \
    && rm -rf /tmp/*


FROM ubuntu:latest

COPY --from=base / /

WORKDIR /erl_modsec

COPY . .
RUN make

RUN mv /rules/*.* /01_crs-setup.conf test/
RUN rm test/REQUEST-922-MULTIPART-ATTACK.conf

ENV LDLIBS=/usr/lib/x86_64-linux-gnu/libmodsecurity.so
RUN make tests
