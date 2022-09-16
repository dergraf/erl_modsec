FROM ubuntu:latest as base

RUN apt-get update -y \
    && apt-get upgrade -y \
    && apt-get install -y wget tmux vim libmodsecurity-dev gnupg2 build-essential \
    && wget https://packages.erlang-solutions.com/erlang-solutions_1.0_all.deb \
    && dpkg -i erlang-solutions_1.0_all.deb \
    && rm -f erlang-solutions_1.0_all.deb \
    && apt-get update -y \
    && apt-get install -y erlang \
    && apt-get -y autoremove \
    && apt-get -y autoclean \
    && rm -rf /tmp/*

FROM ubuntu:latest

COPY --from=base / /

WORKDIR /erl_modsec

# TODO for testing
RUN apt-get install -y git \
    && git clone https://github.com/coreruleset/coreruleset

COPY . .

RUN make 

# TODO Add test coverage
