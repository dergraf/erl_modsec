FROM ubuntu:latest as base

WORKDIR /erl_modsec

RUN apt-get update -y \
    && apt-get upgrade -y \
    && apt-get install -y \
        libmodsecurity-dev \
        build-essential \
        curl git \
        erlang \
    && apt-get -y autoremove \
    && apt-get -y autoclean \
    && rm -rf /tmp/* \
    && mkdir test \
    && curl -s https://raw.githubusercontent.com/coreruleset/coreruleset/v4.0/dev/crs-setup.conf.example -o test/01_crs.conf \
	&& rm -Rf test/coreruleset \
	&& cd test \
    && git clone --depth 1 --filter=blob:none --sparse https://github.com/coreruleset/coreruleset \
	&& cd coreruleset \
	&& git sparse-checkout set rules \
	&& rm rules/REQUEST-922-MULTIPART-ATTACK.conf

FROM ubuntu:latest

COPY --from=base / /

WORKDIR /erl_modsec

COPY LICENSE ./LICENSE 
COPY README.md ./README.md
COPY erlang.mk ./erlang.mk
COPY Makefile ./Makefile
COPY src/ ./src/
COPY c_src/ ./c_src/
COPY test/ ./test/

ENV LDLIBS=/usr/lib/x86_64-linux-gnu/libmodsecurity.so
RUN make -f erlang.mk tests
