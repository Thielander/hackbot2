PREFIX  ?= /usr/local
BINDIR   = $(PREFIX)/bin
ETCDIR   = $(PREFIX)/etc/hackbot2

.PHONY: install uninstall check

install:
	@echo "Installing HackBot2 to $(PREFIX)..."
	install -d $(BINDIR) $(ETCDIR)
	install -m 755 hackbot2.pl $(BINDIR)/hackbot2
	install -m 644 cgi.db          $(ETCDIR)/cgi.db
	install -m 644 fingerprint.db  $(ETCDIR)/fingerprint.db
	install -m 644 disclosure.db   $(ETCDIR)/disclosure.db
	install -m 644 hackbot2.conf   $(ETCDIR)/hackbot2.conf
	@echo "Done. Run: hackbot2 --help"

uninstall:
	rm -f  $(BINDIR)/hackbot2
	rm -rf $(ETCDIR)
	@echo "HackBot2 uninstalled."

check:
	@perl -c hackbot2.pl && echo "Syntax OK"
	@perl -e 'use IO::Socket::INET;  print "IO::Socket::INET  OK\n"'
	@perl -e 'use JSON::PP;          print "JSON::PP          OK\n"'
	@perl -e 'use Term::ANSIColor;   print "Term::ANSIColor   OK\n"'
	@perl -e 'eval { require IO::Socket::SSL }; if ($$@) { print "IO::Socket::SSL   NOT installed (HTTPS scan disabled)\n" } else { print "IO::Socket::SSL   OK\n" }'
