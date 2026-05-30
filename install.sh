#!/bin/bash
# HackBot2 installer
set -e

PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
ETCDIR="$PREFIX/etc/hackbot2"

echo "HackBot2 installer"
echo "=================="
echo "Installing to PREFIX=$PREFIX"
echo ""

# Check Perl
if ! command -v perl &>/dev/null; then
    echo "ERROR: Perl not found. Install perl first." >&2
    exit 1
fi

PERL_VER=$(perl -e 'print $]')
echo "Perl version: $PERL_VER"

# Check optional SSL module
if perl -e 'use IO::Socket::SSL' 2>/dev/null; then
    echo "IO::Socket::SSL: available (HTTPS scanning enabled)"
else
    echo "IO::Socket::SSL: NOT installed (HTTPS scanning disabled)"
    echo "  Install with: sudo cpan IO::Socket::SSL"
    echo "             or: sudo apt install libio-socket-ssl-perl"
fi

echo ""

# Create directories
mkdir -p "$BINDIR" "$ETCDIR"

# Install files
install -m 755 hackbot2.pl "$BINDIR/hackbot2"
install -m 644 cgi.db         "$ETCDIR/cgi.db"
install -m 644 fingerprint.db "$ETCDIR/fingerprint.db"

echo "Installed:"
echo "  $BINDIR/hackbot2"
echo "  $ETCDIR/cgi.db"
echo "  $ETCDIR/fingerprint.db"
echo ""
echo "Run 'hackbot2 --help' to get started."
