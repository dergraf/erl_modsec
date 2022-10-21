PROJECT = erl_modsec
PROJECT_DESCRIPTION = New project
PROJECT_VERSION = 0.1.0

.PHONY: default
default: all ;

clean::
	rm -Rf test/coreruleset


.PHONY: test
test:
	$(MAKE) test/coreruleset
	$(MAKE) -f erlang.mk tests

test/coreruleset:
	curl https://raw.githubusercontent.com/coreruleset/coreruleset/v4.0/dev/crs-setup.conf.example -o test/01_crs.conf
	rm -Rf test/coreruleset
	cd test && \
		git clone --depth 1 --filter=blob:none --sparse https://github.com/coreruleset/coreruleset && \
		cd coreruleset && \
		git sparse-checkout set rules && \
		rm rules/REQUEST-922-MULTIPART-ATTACK.conf



include erlang.mk