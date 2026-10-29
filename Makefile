CC = cc
CFLAGS = -O2 -g
CPPFLAGS =
LDFLAGS =
SYSTEM_XRDP_LIBDIR = /usr/lib/$(shell $(CC) -dumpmachine)/xrdp
XRDP_LIBDIR ?= $(if $(wildcard build/local-api/libxrdpapi.so),$(abspath build/local-api),$(SYSTEM_XRDP_LIBDIR))
XRDP_API_COMMIT = 85c863dba6b2e4863b8760475c8faa7f1b169fdd
PROBE_RPATH ?= $(XRDP_LIBDIR)
PREFIX ?= $(HOME)/.local
PYTHON ?= .venv/bin/python
JS ?= gjs

.PHONY: all test install clean local-api extension-package extension-icons
all: build/rdpewa-probe

extension-package:
	$(PYTHON) tools/package_extension.py

extension-icons:
	$(JS) tools/generate_extension_icons.js

build:
	mkdir -p $@

build/rdpewa-probe: probe.c xrdpapi_compat.h $(XRDP_LIBDIR)/libxrdpapi.so | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c11 -Wall -Wextra -Werror -Wpedantic \
		$(LDFLAGS) probe.c -L$(XRDP_LIBDIR) -Wl,-rpath,$(PROBE_RPATH) -lxrdpapi -o $@

build/libxrdpapi.so: tests/fake_xrdpapi.c xrdpapi_compat.h | build
	$(CC) $(CPPFLAGS) $(CFLAGS) -std=c11 -Wall -Wextra -Werror -Wpedantic \
		-fPIC -shared tests/fake_xrdpapi.c -o $@

build/xrdpapi-src/.ready: | build
	@set -e; for file in xrdpapi/xrdpapi.c xrdpapi/xrdpapi.h \
		common/log.h common/arch.h common/defines.h common/list.h \
		common/string_calls.h common/xrdp_sockets.h COPYING; do \
		mkdir -p "build/xrdpapi-src/$$(dirname "$$file")"; \
		curl --fail --location --silent --show-error \
			"https://raw.githubusercontent.com/neutrinolabs/xrdp/$(XRDP_API_COMMIT)/$$file" \
			-o "build/xrdpapi-src/$$file"; \
	done
	touch $@

build/local-api/libxrdpapi.so: build/xrdpapi-src/.ready patches/xrdpapi-open-timeout.patch
	mkdir -p build/local-api
	cp build/xrdpapi-src/xrdpapi/xrdpapi.c build/local-api/xrdpapi.c
	patch --batch --fuzz=0 build/local-api/xrdpapi.c patches/xrdpapi-open-timeout.patch
	$(CC) $(CPPFLAGS) $(CFLAGS) -Wall -Wextra -fPIC -shared \
		-DCONFIG_AC_H -DHAVE_STDINT_H -DHAVE_FUNC_ATTRIBUTE_FORMAT \
		-DXRDP_SOCKET_PATH='"/run/xrdp/sockdir"' \
		-Ibuild/xrdpapi-src/common -Ibuild/xrdpapi-src/xrdpapi \
		$(LDFLAGS) build/local-api/xrdpapi.c -L$(SYSTEM_XRDP_LIBDIR) \
		-Wl,-rpath,$(SYSTEM_XRDP_LIBDIR) -Wl,-soname,libxrdpapi.so.0 \
		-lcommon -o $@
	ln -sf libxrdpapi.so build/local-api/libxrdpapi.so.0

local-api: build/local-api/libxrdpapi.so

test: build/rdpewa-probe build/libxrdpapi.so
	$(PYTHON) -m unittest discover -s tests -v
	$(JS) tests/test_worker.js

install: build/rdpewa-probe
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -m 755 $< "$(DESTDIR)$(PREFIX)/bin/rdpewa-probe"

clean:
	rm -f build/rdpewa-probe build/libxrdpapi.so
