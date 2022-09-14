# erl_modsec

An Erlang NIF wrapper to libmodsecurity3


## Prerequisites

libmodsecurity3 and the C header files must be present on the system.
Depending on the location of the library and include files you must export the LDLIBS and CFLAGS environment variables prior running `make`.