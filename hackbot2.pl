#!/usr/bin/perl

use strict;
use warnings;
use 5.010;

our $VERSION = '3.0.0';

# HackBot - Network Security Scanner
#
# Copyright (c) 2000-2002 Marco van Berkum
# Modified and extended by Alexander Thiele, 2026
#
# Original authors:
#   Marco van Berkum          <m.v.berkum@obit.nl>
#   Kristian Vlaardingerbroek <kris@obit.nl>
#   Pepijn Vissers            <zoef@zoefdehaas.nl>
#   Herman Poortermans        <herman@ofzo.nl>
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU Lesser General Public License v2.1.
# See LICENSE for details.

use IO::Socket::INET;
use IO::Socket;
use Net::hostent;
use Getopt::Long qw(:config no_ignore_case bundling);
use Socket qw(inet_ntoa unpack_sockaddr_in);
use POSIX qw(strftime);
use JSON::PP ();
use Term::ANSIColor qw(colored);
use Scalar::Util qw(looks_like_number);
use FindBin qw($Bin);

my $ssl_available = eval { require IO::Socket::SSL; IO::Socket::SSL->import(); 1 };

# --------------------------------------------------------------------------
# Default options
# --------------------------------------------------------------------------
my %opt = (
    color => (-t STDOUT) ? 1 : 0,
    T     => 5,
    l     => 'c',
);

GetOptions(
    'A'         => \$opt{A},
    'i'         => \$opt{i},
    't'         => \$opt{t},
    'f'         => \$opt{f},
    'm'         => \$opt{m},
    's'         => \$opt{s},
    'S'         => \$opt{S},
    'd'         => \$opt{d},
    'r'         => \$opt{r},
    'V|version' => \$opt{V},
    'w=s'       => \$opt{w},
    'z=i'       => \$opt{z},
    'a=i'       => \$opt{a},
    'X'         => \$opt{X},
    'F=s'       => \$opt{F},
    'O=s'       => \$opt{O},
    'P=s'       => \$opt{P},
    'l=s'       => \$opt{l},
    'H'         => \$opt{H},
    'g'         => \$opt{g},
    'p'         => \$opt{p},
    'n'         => \$opt{n},
    'b'         => \$opt{b},
    'e'         => \$opt{e},
    'B'         => \$opt{B},
    'j|json'    => \$opt{j},
    'color!'    => \$opt{color},
    'T=i'       => \$opt{T},
    'help|h'    => \$opt{help},
) or usage();

usage() if $opt{help};

if ($opt{V}) {
    print "HackBot version $VERSION\n";
    exit 0;
}

# --------------------------------------------------------------------------
# State variables
# --------------------------------------------------------------------------
my ($host, $target, $targetfile, $port, $proxy, $proxyport);
my ($host_resolves, $noweb, $nowhois, $range, $noprint);
my ($start, $end);
my @targetlist;
my %json_results;

# Database paths: prefer installed location, fall back to script directory
my $db_path   = $ENV{HACKBOT_DB}      // (-e '/usr/local/etc/hackbot2/cgi.db'
    ? '/usr/local/etc/hackbot2/cgi.db'          : "$Bin/cgi.db");
my $fp_db     = $ENV{HACKBOT_FPDB}    // (-e '/usr/local/etc/hackbot2/fingerprint.db'
    ? '/usr/local/etc/hackbot2/fingerprint.db'  : "$Bin/fingerprint.db");
my $disc_db   = $ENV{HACKBOT_DISCDB}  // (-e '/usr/local/etc/hackbot2/disclosure.db'
    ? '/usr/local/etc/hackbot2/disclosure.db'   : "$Bin/disclosure.db");


my @SUBDOMAIN_WORDLIST = qw(
    www www2 www3 mail mail2 smtp smtp2 pop pop3 imap imap2 webmail
    ftp sftp ssh ns1 ns2 ns3 ns4 mx mx1 mx2 mx3 relay
    vpn remote access gateway proxy firewall waf
    dev dev2 staging stage test qa uat beta alpha sandbox demo preview lab
    admin admin2 administrator manage panel dashboard backend cpanel whm plesk webmin
    api api2 api3 v1 v2 v3 rest graphql ws rpc
    app app2 apps portal client customer member account login auth sso oauth
    cdn static assets media img images files storage upload uploads
    git gitlab github bitbucket svn repo
    jira confluence wiki docs kb helpdesk support ticket
    ci cd jenkins build deploy pipeline
    monitor monitoring grafana prometheus kibana status health metrics
    blog forum community shop store pay billing crm erp hr
    internal intranet extranet corp office
    db database mysql postgres redis mongo cache elasticsearch
    cloud k8s registry docker
    m mobile wap
    old legacy backup archive new
    video audio stream live
    search autocomplete
    sandbox local
);

# --------------------------------------------------------------------------
# Argument validation
# --------------------------------------------------------------------------
if ($opt{F}) {
    chomp($targetfile = $opt{F});
} else {
    $host = $ARGV[0];
    # Strip trailing slashes, spaces, protocol prefix (http://, https://)
    if (defined $host) {
        $host =~ s|^\s*https?://||i;
        $host =~ s|/.*$||;
        $host =~ s|\s+$||;
    }
}

usage() unless ($opt{F} || $host);

if ($opt{F} && $host) {
    die "Error: cannot use -F together with a host argument.\n";
}

if ($opt{l} && $opt{l} !~ /^[cdv]+$/) {
    die "Unknown log level '$opt{l}'. Use c, v, or d.\n";
}

if ($opt{w} && $opt{w} !~ /^[aocivshd]+$/) {
    die "Unknown webserver scan type '$opt{w}'.\n";
}

$port = $opt{a} // 80;

if (($opt{a} || $opt{z}) && !$opt{A} && !$opt{w}) {
    die "Options -a and -z require -w or -A.\n";
}

# --------------------------------------------------------------------------
# Proxy setup
# --------------------------------------------------------------------------
if ($opt{P}) {
    ($proxy, $proxyport) = split(/:/, $opt{P}, 2);
    $proxy    //= ''; chomp $proxy;
    $proxyport //= ''; chomp $proxyport;

    if ($proxy =~ /[a-zA-Z]/) {
        log_print("Resolving proxy host $proxy\n", 'h');
        my $handler = gethost($proxy);
        if (!$handler) {
            log_print("Proxy $proxy does not resolve, continuing without proxy\n\n", 'c');
            undef $proxy; undef $proxyport;
        } else {
            $proxy = inet_ntoa($handler->addr_list->[0]);
            log_print("Proxy resolved to $proxy\n", 'c');
            log_print("Testing proxy...\n\n", 'h');
            proxytest($proxy, $host // '');
        }
    } else {
        proxytest($proxy, $host // '');
    }
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
print "\n";
banner();
log_print(strftime("%Y-%m-%d %H:%M:%S", localtime) . "\n\n", 'c');

if ($opt{F}) {
    open(my $fh, '<', $targetfile) or die "Cannot open '$targetfile': $!\n";
    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^#/;
        push @targetlist, $_;
    }
    close $fh;

    for $host (@targetlist) {
        log_print("Checking $host ...\n\n", 'h');
        scanit();
    }
} else {
    if ($host =~ /[a-zA-Z]/) {
        log_print("Checking named host $host ...", 'c');
        scanit();
    } else {
        get_range();
        $range = 1;
        log_print("Range scan from $start to $end\n", 'c') unless $start eq $end;
        for $host (@targetlist) {
            log_print("\nChecking $host ...\n\n", 'c');
            scanit();
        }
    }
}

endbanner();
output_json() if $opt{j};
exit 0;

# --------------------------------------------------------------------------
# Scan dispatcher
# --------------------------------------------------------------------------
sub scanit {
    if (!check_ip($host)) {
        log_print(" resolving $host ...\n\n", 'c');
        my $handler = gethost($host);
        if (!$handler) {
            log_print("$host does not resolve, skipping.\n\n", 'c');
            return;
        }
        $target = inet_ntoa($handler->addr_list->[0]);
        log_print("Resolved to: $target\n\n", 'i');
        $host_resolves = 1;
    } else {
        $target = $host;
        $host_resolves = 0;
    }

    if ($opt{A}) {
        @opt{qw(i t f m s S d r X H g p n b e B)} = (1) x 16;
        $opt{w} = 'a';
    }

    header_reset(); spamcheck()      if $opt{S};
    header_reset(); ident_scan()     if $opt{i};
    header_reset(); telnetfprint()   if $opt{t};
    header_reset(); ftp_scan()       if $opt{f};
    header_reset(); mta_scan()       if $opt{m};
    header_reset(); ssh_scan()       if $opt{s};
    header_reset(); dns_scan()       if $opt{d};
    header_reset(); whois_lookup()   if $opt{r} && !$nowhois;
    $nowhois = $range;
    header_reset(); xcheck()         if $opt{X};
    header_reset(); geolocation()    if $opt{g};
    header_reset(); port_scan()      if $opt{p};
    header_reset(); https_scan()     if $opt{H};
    header_reset(); os_detect()      if $opt{n};
    header_reset(); email_security()   if $opt{e} && !check_ip($host);
    header_reset(); service_banners()  if $opt{B};
    header_reset(); subdomain_scan() if $opt{b} && !check_ip($host);

    if ($opt{w}) {
        header_reset();
        checkweb();
        unless ($noweb) {
            if ($opt{w} =~ /[oa]/) { header_reset(); http_options();      }
            if ($opt{w} =~ /[ca]/) { header_reset(); cgi_scan();          }
            if ($opt{w} =~ /[sa]/) { header_reset(); security_headers();
                                     header_reset(); cookie_check();
                                     header_reset(); cors_check();        }
            if ($opt{w} =~ /[a]/)  { header_reset(); redirect_chain();
                                     header_reset(); cms_detect();
                                     header_reset(); tech_stack_print();
                                     header_reset(); error_page_fingerprint();
                                     header_reset(); mixed_content_check();  }
            if ($opt{w} =~ /[da]/) { header_reset(); disclosure_scan();   }
        }
    }
}

# --------------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------------
sub check_ip {
    my ($ip) = @_;
    return 0 unless defined $ip && $ip =~ /^[0-9.]+$/;
    return 0 unless $ip =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/;
    for ($1, $2, $3, $4) { return 0 if $_ > 255 }
    return 1;
}

sub is_private_ip {
    my ($ip) = @_;
    return $ip =~ /^(10\.|127\.|169\.254\.|
                     172\.(1[6-9]|2[0-9]|3[01])\.|
                     192\.168\.)/x;
}

# --------------------------------------------------------------------------
# Banner
# --------------------------------------------------------------------------
sub banner {
    my $sep = '#' x 65;
    log_print("$sep\n", 'c');
    log_print("#  HackBot v$VERSION - Network Security Scanner       " . ' ' x (65 - 47 - length($VERSION)) . "#\n", 'c');
    log_print("#  Based on HackBot (c) 2000-2002 Marco van Berkum            #\n", 'c');
    log_print("#  Modified and extended by Alexander Thiele, 2026            #\n", 'c');
    log_print("#                                                             #\n", 'c');
    log_print("#  Alexander Thiele - alexander\@thiele.es                    #\n", 'c');
    log_print("#  Marco van Berkum                                           #\n", 'c');
    log_print("#  Kristian Vlaardingerbroek                                  #\n", 'c');
    log_print("#  Pepijn Vissers                                             #\n", 'c');
    log_print("#  Herman Poortermans                                         #\n", 'c');
    log_print("$sep\n\n", 'c');
}

# --------------------------------------------------------------------------
# Subdomain scanner — CT logs + DNS brute-force + AXFR (new in v3)
# --------------------------------------------------------------------------

sub subdomain_scan {
    return if check_ip($host);

    my $domain = _base_domain($host);
    unless ($domain) {
        log_print("Cannot determine base domain for subdomain scan\n\n", 'i');
        return;
    }

    log_print("Subdomain scan: $domain\n", 'h');
    log_print("-" x (17 + length $domain) . "\n", 'h');

    my %found;   # subdomain => source

    # --- Wildcard DNS detection ---
    # Query a random non-existent subdomain; if it resolves, all responses
    # with that IP are wildcard false positives and must be filtered out.
    my $wildcard_ip;
    {
        my $rand = "hackbot-noexist-" . int(rand 999999);
        my $h = gethost("$rand.$domain");
        if ($h) {
            $wildcard_ip = inet_ntoa($h->addr_list->[0]);
            log_print("Wildcard DNS detected: *.$domain -> $wildcard_ip (false positives will be filtered)\n", 'c');
        }
    }

    # --- Source 1: Certificate Transparency via crt.sh ---
    log_print("Querying Certificate Transparency logs (crt.sh)...\n", 'h');
    if ($ssl_available) {
        my $sock = IO::Socket::SSL->new(
            PeerAddr        => 'crt.sh', PeerPort => 443,
            Proto           => 'tcp',    Timeout  => 15,
            SSL_verify_mode => 0,        SSL_hostname => 'crt.sh',
        );
        if ($sock) {
            print $sock "GET /?q=%25.$domain&output=json HTTP/1.1\r\n"
                      . "Host: crt.sh\r\nConnection: close\r\n\r\n";
            my $resp = _ssl_read($sock);
            close $sock;

            my (undef, $body) = split(/\r?\n\r?\n/, $resp // '', 2);
            if ($body) {
                # crt.sh may return chunked
                $body = _decode_chunked($body) if ($resp // '') =~ /transfer-encoding:\s*chunked/i;
                my $data = eval { JSON::PP::decode_json($body) } // [];
                for my $entry (@$data) {
                    for my $name (split(/\n/, $entry->{name_value} // ''),
                                  $entry->{common_name} // '') {
                        $name = lc $name;
                        $name =~ s/^\*\.//;
                        next if $name =~ /\*/;
                        next unless $name =~ /\Q$domain\E$/;
                        $found{$name} //= 'crt.sh';
                    }
                }
            }
            my $ct_count = scalar grep { $found{$_} eq 'crt.sh' } keys %found;
            log_print("crt.sh: $ct_count unique subdomains found\n", 'c');
        } else {
            log_print("crt.sh unreachable (IO::Socket::SSL required)\n", 'i');
        }
    } else {
        log_print("IO::Socket::SSL not installed, skipping crt.sh lookup\n", 'i');
    }

    # --- Source 2: DNS Zone Transfer (AXFR) ---
    log_print("Attempting DNS zone transfer (AXFR)...\n", 'h');
    {
        open(my $ns_fh, '-|', 'dig', '+short', 'NS', $domain) or goto SKIP_AXFR;
        my @nameservers = map { chomp; s/\.$//; $_ } <$ns_fh>;
        close $ns_fh;

        my $axfr_ok = 0;
        for my $ns (@nameservers) {
            open(my $axfr, '-|', 'dig', 'AXFR', $domain, '@' . $ns) or next;
            my $out = do { local $/; <$axfr> };
            close $axfr;
            next unless $out && $out !~ /Transfer failed|REFUSED|SERVFAIL|no servers could be reached/i;

            while ($out =~ /^(\S+)\s+\d+\s+IN\s+A\s/gm) {
                my $sub = lc $1;
                $sub =~ s/\.$//;
                next unless $sub =~ /\Q$domain\E$/;
                $found{$sub} //= 'AXFR';
                $axfr_ok = 1;
            }
        }
        log_print($axfr_ok ? "AXFR succeeded\n" : "AXFR refused (normal)\n", 'i');
    }
    SKIP_AXFR:

    # --- Source 3: DNS Brute-Force ---
    my $bf_total = scalar @SUBDOMAIN_WORDLIST;
    log_print("DNS brute-force ($bf_total names)...\n", 'h');
    my $bf_found = 0;
    my $bf_idx   = 0;
    for my $word (@SUBDOMAIN_WORDLIST) {
        $bf_idx++;
        printf STDERR "\r  probing %d/%d: %-40s", $bf_idx, $bf_total, "$word.$domain"
            unless $opt{j};
        my $fqdn = "$word.$domain";
        next if exists $found{$fqdn};
        my $handler = gethost($fqdn);
        if ($handler) {
            $found{$fqdn} //= 'bruteforce';
            $bf_found++;
        }
    }
    print STDERR "\r" . ' ' x 70 . "\r" unless $opt{j};
    log_print("Brute-force: $bf_found new subdomains found\n", 'c');

    # --- Resolve all found subdomains and filter wildcard responses ---
    my %resolved;   # subdomain => ip
    for my $sub (keys %found) {
        my $h = gethost($sub);
        next unless $h;
        my $ip = inet_ntoa($h->addr_list->[0]);
        # Skip wildcard false positives (only filter bruteforce, keep CT/AXFR)
        next if $wildcard_ip && $ip eq $wildcard_ip && $found{$sub} eq 'bruteforce';
        $resolved{$sub} = $ip;
    }

    # --- Report ---
    log_print("\n", 'c');
    if (%resolved) {
        log_print(sprintf("%-45s %-12s %s\n", 'Subdomain', 'Source', 'IP'), 'c');
        log_print("-" x 75 . "\n", 'c');

        for my $sub (sort keys %resolved) {
            log_print(sprintf("%-45s %-12s %s\n",
                $sub, $found{$sub}, $resolved{$sub}), 'c');
        }

        my $total = scalar keys %resolved;
        log_print("\nTotal: $total confirmed subdomains\n\n", 'c');
        $json_results{subdomains} = [ sort keys %resolved ];
    } else {
        if ($wildcard_ip) {
            log_print("No subdomains found (all responses were wildcard: $wildcard_ip)\n\n", 'i');
        } else {
            log_print("No subdomains found\n\n", 'i');
        }
    }
}

sub _base_domain {
    my ($h) = @_;
    return '' if check_ip($h);
    my @p = split(/\./, $h);
    return '' if @p < 2;
    # Two-part TLDs (co.uk, com.au, net.br…)
    my %two_part = map { $_ => 1 } qw(co.uk com.au net.au org.au
        co.nz net.nz org.nz com.br net.br org.br co.jp ne.jp
        co.za net.za co.in net.in org.in);
    if (@p >= 3 && $two_part{"$p[-2].$p[-1]"}) {
        return join('.', @p[-3..-1]);
    }
    return join('.', @p[-2..-1]);
}

sub endbanner {
    log_print("--->\n", 'c');
    log_print("All scans done. HackBot $VERSION\n", 'c');
    log_print("---> Exiting.\n", 'c');
}

# --------------------------------------------------------------------------
# SSH scan
# --------------------------------------------------------------------------
sub ssh_scan {
    log_print("Checking for SSH\n", 'h');
    log_print("----------------\n", 'h');

    my $sock = IO::Socket::INET->new(
        PeerAddr => $target, PeerPort => 22,
        Proto => 'tcp', Timeout => $opt{T},
    );

    if (!$sock) {
        log_print("No SSH\n\n", 'i');
        return;
    }

    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm($opt{T} + 2);
        sysread($sock, my $buff, 256);
        alarm(0);
        if ($buff) {
            chomp $buff;
            log_print("SSH banner: $buff\n\n", 'c');
            if ($buff =~ /SSH-1\./) {
                log_print("WARNING: SSHv1 detected - insecure, upgrade required!\n\n", 'c');
            }
            $json_results{ssh} = $buff;
        }
    };
    close $sock;
}

# --------------------------------------------------------------------------
# FTP scan
# --------------------------------------------------------------------------
sub ftp_scan {
    log_print("Checking for FTP\n", 'h');
    log_print("----------------\n", 'h');

    my $sock = IO::Socket::INET->new(
        PeerAddr => $target, PeerPort => 21,
        Proto => 'tcp', Timeout => $opt{T},
    );

    if (!$sock) {
        log_print("No FTP\n\n", 'i');
        return;
    }

    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm($opt{T} * 4);

        sysread($sock, my $banner, 1024);
        log_print("FTP banner: $banner\n", 'c') if $banner;

        print $sock "USER anonymous\r\n";
        sleep(1);
        sysread($sock, my $resp1, 256);

        print $sock "PASS hackbot\@example.com\r\n";
        sleep(1);
        sysread($sock, my $resp2, 256);

        if ($resp2 && $resp2 =~ /^230/) {
            log_print("Anonymous login ALLOWED\n", 'c');
            print $sock "CWD upload\r\n";
            sleep(1);
            sysread($sock, my $resp3, 256);
            if ($resp3 && $resp3 =~ /^250/) {
                log_print("Upload directory found\n", 'c');
                print $sock "STOR hackbot_test.tmp\r\n";
                sleep(1);
                sysread($sock, my $resp4, 256);
                if ($resp4 && $resp4 !~ /^553/) {
                    log_print("Write access to upload directory!\n\n", 'c');
                } else {
                    log_print("No write access to upload directory\n\n", 'c');
                }
            }
        } else {
            log_print("Anonymous login not allowed\n\n", 'i');
        }
        alarm(0);
    };
    close $sock;
}

# --------------------------------------------------------------------------
# SMTP/MTA scan
# --------------------------------------------------------------------------
sub mta_scan {
    log_print("MTA - Relay / VRFY / EXPN check\n", 'h');
    log_print("--------------------------------\n", 'h');

    my $sock = IO::Socket::INET->new(
        PeerAddr => $target, PeerPort => 25,
        Proto => 'tcp', Timeout => $opt{T},
    );

    if (!$sock) {
        log_print("No MTA\n\n", 'i');
        return;
    }

    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm($opt{T} * 8);

        sysread($sock, my $banner, 1024);
        log_print("$banner", 'c') if $banner;

        print $sock "EHLO hackbot\r\n";
        sleep(1);
        sysread($sock, my $ehlo, 1024);
        log_print("$ehlo\n", 'd') if $ehlo;

        print $sock "MAIL FROM:<test\@example.com>\r\n";
        sleep(1);
        sysread($sock, my $r1, 256);

        print $sock "RCPT TO:<test\@example.com>\r\n";
        sleep(1);
        sysread($sock, my $r2, 256);

        if ($r2 && $r2 =~ /^250/) {
            log_print("Open relay detected!\n\n", 'c');
        } else {
            log_print("Relaying not allowed\n\n", 'i');
        }

        print $sock "VRFY root\r\n";
        sleep(1);
        sysread($sock, my $vrfy, 256);
        if ($vrfy && $vrfy =~ /^250/) {
            log_print("VRFY enabled: $vrfy\n", 'c');
        } else {
            log_print("VRFY disabled\n\n", 'i');
        }

        print $sock "EXPN root\r\n";
        sleep(1);
        sysread($sock, my $expn, 256);
        if ($expn && $expn =~ /^250/) {
            log_print("EXPN enabled: $expn\n\n", 'c');
        } else {
            log_print("EXPN disabled\n\n", 'i');
        }

        print $sock "QUIT\r\n";
        alarm(0);
    };
    close $sock;
}

# --------------------------------------------------------------------------
# DNS scan
# --------------------------------------------------------------------------
sub dns_scan {
    log_print("DNS scan\n", 'h');
    log_print("--------\n", 'h');

    # BIND version (only when scanning a nameserver directly)
    my $sock = IO::Socket::INET->new(
        PeerAddr => $target, PeerPort => 53,
        Proto => 'tcp', Timeout => $opt{T});

    if ($sock) {
        close $sock;
        open(my $dig, '-|', 'dig', '@' . $target, 'version.bind', 'chaos', 'txt')
            or goto SKIP_BIND;
        my $out = do { local $/; <$dig> };
        close $dig;
        if ($out && $out =~ /"([^"]+)"/) {
            log_print("BIND version: $1\n", 'c');
            $json_results{dns_version} = $1;
        } else {
            log_print("DNS port open but no version returned\n", 'i');
        }
    } else {
        log_print("No DNS server on port 53\n", 'i');
    }
    SKIP_BIND:

    # Full DNS record dump for named hosts
    return if check_ip($host);
    my $domain = $host;

    log_print("\nDNS records for $domain\n", 'h');
    log_print("-" x (17 + length $domain) . "\n", 'h');

    my %records;
    for my $type (qw(A AAAA MX NS TXT SOA CAA)) {
        open(my $fh, '-|', 'dig', '+short', $type, $domain) or next;
        my @recs = grep { /\S/ } <$fh>;
        close $fh;
        chomp @recs;
        next unless @recs;
        $records{$type} = \@recs;
        for my $r (@recs) {
            log_print(sprintf("  %-6s %s\n", $type, $r), 'c');
        }
    }

    # IPv6 reachability
    if ($records{AAAA}) {
        log_print("\n[OK] IPv6 (AAAA) supported\n", 'c');
        my $v6 = $records{AAAA}[0];
        my $sock6 = IO::Socket::INET->new(
            PeerAddr => $v6, PeerPort => 80,
            Proto => 'tcp', Timeout => $opt{T});
        if ($sock6) {
            log_print("[OK] IPv6 address $v6 reachable on port 80\n", 'c');
            close $sock6;
        } else {
            log_print("[i]  IPv6 address $v6 not reachable on port 80\n", 'i');
        }
    } else {
        log_print("\n[!]  No AAAA record — IPv6 not supported\n", 'i');
    }

    # CAA advisory
    if ($records{CAA}) {
        log_print("\n[OK] CAA records present — certificate issuance restricted\n", 'c');
    } else {
        log_print("\n[!]  No CAA record — any CA can issue certificates for this domain\n", 'i');
    }

    # DANE / TLSA
    open(my $tlsa_fh, '-|', 'dig', '+short', 'TLSA', "_443._tcp.$domain") or goto SKIP_TLSA;
    my @tlsa = grep { /\S/ } <$tlsa_fh>;
    close $tlsa_fh;
    if (@tlsa) {
        chomp @tlsa;
        log_print("[OK] DANE/TLSA record found: $tlsa[0]\n", 'c');
    } else {
        log_print("[i]  No DANE/TLSA record (optional but good for email MTAs)\n", 'i');
    }
    SKIP_TLSA:

    log_print("\n", 'c');
    $json_results{dns_records} = \%records;
}

# --------------------------------------------------------------------------
# HTTP webserver check
# --------------------------------------------------------------------------
sub checkweb {
    undef $noweb;
    log_print("Checking webserver on port $port\n", 'h');
    log_print("---------------------------------\n", 'h');

    my $sock = IO::Socket::INET->new(
        PeerAddr => $target, PeerPort => $port,
        Proto => 'tcp', Timeout => $opt{T},
    );

    if (!$sock) {
        $noweb = 1;
        log_print("No webserver on port $port\n\n", 'i');
        return;
    }

    my $host_hdr = $host_resolves ? $host : $target;
    print $sock "HEAD / HTTP/1.1\r\nHost: $host_hdr\r\nConnection: close\r\n\r\n";
    sleep(2);
    sysread($sock, my $resp, 8192);
    close $sock;

    if ($resp) {
        log_print("$resp\n", 'c') if $opt{w} =~ /[va]/;
        log_print("Webserver found\n\n", 'c') unless $opt{w} =~ /[va]/;
        check_server_version($resp);
        $json_results{http_banner} = (split(/\r?\n/, $resp))[0];

        # Detect HTTP→HTTP redirect (no HTTPS) and warn
        if ($resp =~ /^Location:\s*http:\/\//im && $resp =~ /^HTTP\/\S+\s+30[12]/m) {
            log_print("[!] Server redirects to plain HTTP — no HTTPS in use!\n", 'c');
            log_print("    Security header checks will run on HTTP (no encryption)\n\n", 'c');
        }
    }
}

sub check_server_version {
    my ($resp) = @_;

    if ($resp =~ /Server:\s*(.+)/i) {
        my $srv = $1;
        chomp $srv;
        log_print("Server: $srv\n", 'c');
        $json_results{server} = $srv;

        # Apache version advisory
        if ($srv =~ /Apache\/(\d+\.\d+)\.(\d+)/i) {
            my ($maj, $min) = ($1, $2);
            if ($maj eq '2.4' && $min < 58) {
                log_print("WARNING: Apache $maj.$min may have known vulnerabilities - update to 2.4.58+\n", 'c');
            } elsif ($maj eq '2.2' || $maj eq '1.3') {
                log_print("WARNING: Apache $maj is end-of-life!\n", 'c');
            }
        }

        # nginx advisory
        if ($srv =~ /nginx\/(\d+\.\d+\.\d+)/i) {
            log_print("nginx $1 detected\n", 'c');
        }

        # PHP version leak
        if ($resp =~ /X-Powered-By:\s*(PHP[^\r\n]+)/i) {
            log_print("$1 exposed in headers - consider hiding with expose_php=Off\n", 'c');
        }
    }
    log_print("\n", 'c');
}

# --------------------------------------------------------------------------
# HTTP OPTIONS
# --------------------------------------------------------------------------
sub http_options {
    log_print("HTTP OPTIONS\n", 'h');
    log_print("------------\n", 'h');

    my $sock = IO::Socket::INET->new(
        PeerAddr => $target, PeerPort => $port,
        Proto => 'tcp', Timeout => $opt{T},
    );
    return unless $sock;

    my $host_hdr = $host_resolves ? $host : $target;
    print $sock "OPTIONS / HTTP/1.1\r\nHost: $host_hdr\r\nConnection: close\r\n\r\n";
    sysread($sock, my $buff, 4096);
    close $sock;

    if ($buff) {
        if ($buff =~ /^Allow:\s*(.+)$/im)  { log_print("Allow:  $1\n", 'c'); }
        if ($buff =~ /^Public:\s*(.+)$/im) { log_print("Public: $1\n", 'c'); }

        # Flag dangerous HTTP methods
        if ($buff =~ /\b(TRACE|PUT|DELETE|CONNECT)\b/i) {
            log_print("WARNING: Potentially dangerous HTTP methods enabled: $1\n", 'c');
        }
    }
    log_print("\n", 'c');
}

# --------------------------------------------------------------------------
# CGI scan
# --------------------------------------------------------------------------
sub cgi_scan {
    unless (-e $db_path) {
        log_print("CGI database not found (expected: $db_path)\n\n", 'c');
        return;
    }

    open(my $fh, '<', $db_path) or do {
        log_print("Cannot open CGI database: $!\n\n", 'c');
        return;
    };

    log_print("CGI vulnerability scan (port $port)\n", 'h');
    log_print("------------------------------------\n", 'h');

    my $host_hdr = $host_resolves ? $host : $target;

    while (<$fh>) {
        chomp;
        next if /^\s*$/ || /^#/;
        my ($path, $desc, $advisory) = split(/!/, $_, 3);
        next unless $path;

        sleep($opt{z}) if $opt{z};

        my $sock = IO::Socket::INET->new(
            PeerAddr => $proxy // $target,
            PeerPort => $proxy ? $proxyport : $port,
            Proto => 'tcp', Timeout => $opt{T},
        );
        next unless $sock;

        if ($proxy) {
            my $url_host = $host_resolves ? $host : $target;
            print $sock "GET http://$url_host$path HTTP/1.0\r\n\r\n";
        } else {
            print $sock "GET $path HTTP/1.0\r\nHost: $host_hdr\r\n\r\n";
        }

        sysread($sock, my $buff, 4096);
        close $sock;

        if ($buff && $buff =~ /^HTTP\/\d\.\d 200/) {
            log_print("FOUND: $path\n", 'c');
            log_print("  $desc\n", 'c') if $desc;
            log_print("  $advisory\n", 'c') if $advisory;
            log_print("\n", 'c');
        }
    }
    close $fh;
}

# --------------------------------------------------------------------------
# Disclosure / common file scan (new in v3)
# --------------------------------------------------------------------------
my %severity_color = (
    INFO     => '',
    LOW      => '',
    MEDIUM   => '',
    HIGH     => '',
    CRITICAL => '',
);

sub disclosure_scan {
    unless (-e $disc_db) {
        log_print("Disclosure database not found ($disc_db)\n\n", 'c');
        return;
    }

    open(my $fh, '<', $disc_db) or do {
        log_print("Cannot open disclosure database: $!\n\n", 'c');
        return;
    };

    # Pre-load entries so we know the total for the progress bar
    my @entries = grep { /\S/ && !/^#/ } <$fh>;
    close $fh;
    my $total   = scalar @entries;
    my $current = 0;

    log_print("Disclosure / common file scan\n", 'h');
    log_print("-----------------------------\n", 'h');

    my $host_hdr  = $host_resolves ? $host : $target;
    my $use_https = $ssl_available && !$noweb;
    my %found;

    for my $line (@entries) {
        chomp $line;
        next if $line =~ /^\s*$/ || $line =~ /^#/;
        my ($path, $category, $severity, $desc) = split(/!/, $line, 4);
        next unless $path;

        $current++;
        # Progress on STDERR (not written to output file)
        printf STDERR "\r  scanning %d/%d: %-45s", $current, $total, $path
            unless $opt{j};

        sleep($opt{z}) if $opt{z};

        my ($resp_code, $resp_body, $content_type, $content_length) =
            _http_fetch($path, $host_hdr, $use_https, 1);  # 1 = use persistent connection

        next unless $resp_code;
        next unless $resp_code == 200 || $resp_code == 301 || $resp_code == 302;

        # Skip likely false positives
        next if defined $content_length && $content_length eq '0';
        # For HEAD requests body is always empty — use Content-Length header instead
        my $body_len = ($content_length && $content_length =~ /^\d+$/)
                       ? $content_length + 0
                       : length($resp_body);
        next if $body_len < 8 && $category ne 'admin' && $category ne 'disclosure';

        my $sev_tag = sprintf("%-8s", "[$severity]");

        if ($resp_code =~ /^30/) {
            # Redirects for admin panels count as a finding
            next unless $category eq 'admin';
            log_print("$sev_tag $path  -> redirect ($resp_code)\n", 'c');
            $found{$severity}++;
        } else {
            log_print("$sev_tag $path\n", 'c');
            log_print("  Category: $category | $desc\n", 'c');

            # For robots/feed/llms and similar: just show the URL, no content dump
            if ($category eq 'disclosure') {
                my $proto = $ssl_available ? 'https' : 'http';
                my $url_host = $host_resolves ? $host : $target;
                log_print("  URL:  $proto://$url_host$path\n", 'c');
            }

            # For sensitive files: show first line only (enough to confirm it's real)
            if ($severity =~ /^(HIGH|CRITICAL)$/ && $category =~ /^(config|git|backup|log)$/) {
                my ($first_line) = split(/\r?\n/, $resp_body);
                $first_line //= '';
                $first_line = substr($first_line, 0, 120);
                log_print("  Preview:  $first_line\n", 'c') if $first_line =~ /\S/;
            }

            $found{$severity}++;
            push @{$json_results{disclosure}}, {
                path     => $path,
                category => $category,
                severity => $severity,
                desc     => $desc,
            };
        }
        log_print("\n", 'c');
    }

    # Clear progress line and close persistent connection
    print STDERR "\r" . ' ' x 70 . "\r" unless $opt{j};

    if (%found) {
        log_print("Summary: " . join(', ', map { "$found{$_} $_" } sort keys %found) . "\n\n", 'c');
    } else {
        log_print("No sensitive files found\n\n", 'i');
    }
}

# Fetch a path via HTTPS (preferred) or HTTP.
# Returns (status_code, body, content-type, content-length).
# $fast=1: HEAD request, 2s timeout — used by disclosure_scan for speed.
sub _http_fetch {
    my ($path, $host_hdr, $use_https, $fast) = @_;
    my $timeout = $fast ? 2 : $opt{T};
    my $method  = $fast ? 'HEAD' : 'GET';
    my $resp_raw;

    if ($use_https && $ssl_available) {
        my $s = IO::Socket::SSL->new(
            PeerAddr => $target, PeerPort => 443, Proto => 'tcp',
            Timeout => $timeout, SSL_verify_mode => 0, SSL_hostname => $host_hdr,
        );
        if ($s) {
            print $s "$method $path HTTP/1.1\r\nHost: $host_hdr\r\nConnection: close\r\n\r\n";
            if ($fast) {
                my $buf = '';
                eval {
                    local $SIG{ALRM} = sub { die "timeout\n" };
                    alarm($timeout + 1);
                    # Read chunks until we see end-of-headers
                    while (length($buf) < 8192) {
                        my $chunk;
                        last unless sysread($s, $chunk, 512);
                        $buf .= $chunk;
                        last if $buf =~ /\r?\n\r?\n/;
                    }
                    alarm(0);
                };
                $resp_raw = $buf;
            } else {
                $resp_raw = _ssl_read($s);
            }
            close $s;
        }
    }
    unless ($resp_raw) {
        my $s = IO::Socket::INET->new(
            PeerAddr => $target, PeerPort => $port,
            Proto => 'tcp', Timeout => $timeout);
        if ($s) {
            print $s "$method $path HTTP/1.1\r\nHost: $host_hdr\r\nConnection: close\r\n\r\n";
            my $buf = '';
            eval {
                local $SIG{ALRM} = sub { die "timeout\n" };
                alarm($timeout + 1);
                sysread($s, $buf, $fast ? 4096 : 32768);
                alarm(0);
            };
            $resp_raw = $buf;
            close $s;
        }
    }

    return () unless $resp_raw;

    # HEAD has no body — ensure there's a separator so split works
    $resp_raw .= "\r\n\r\n" unless $resp_raw =~ /\r?\n\r?\n/;

    my ($header_block, $body) = split(/\r?\n\r?\n/, $resp_raw, 2);
    return () unless $header_block;

    my ($status_line, @header_lines) = split(/\r?\n/, $header_block);
    my ($resp_code) = $status_line =~ /HTTP\/[\d.]+ (\d+)/;
    return () unless $resp_code;

    my %headers;
    $headers{lc $1} = $2 for grep { /^([^:]+):\s*(.+)/ } @header_lines;

    $body = _decode_chunked($body)
        if ($headers{'transfer-encoding'} // '') =~ /chunked/i && defined $body;

    return ($resp_code + 0, $body // '', $headers{'content-type'} // '', $headers{'content-length'} // '');
}

sub _decode_chunked {
    my ($data) = @_;
    my $out = '';
    while ($data =~ s/^([0-9a-fA-F]+)\r?\n//) {
        my $size = hex($1);
        last if $size == 0;
        last if $size > length($data);   # incomplete chunk — partial read, stop here
        $out  .= substr($data, 0, $size);
        $data  = substr($data, $size);
        $data  =~ s/^\r?\n//;
    }
    return $out || $data;
}

# --------------------------------------------------------------------------
# HTTP Redirect Chain (new in v3)
# --------------------------------------------------------------------------
sub redirect_chain {
    log_print("Redirect Chain\n", 'h');
    log_print("--------------\n", 'h');

    my $cur_host   = $target;
    my $cur_hdr    = $host_resolves ? $host : $target;
    my $cur_port   = $port;
    my $use_ssl    = 0;
    my $path       = '/';
    my @chain;

    for my $hop (1..10) {
        my $resp;
        if ($use_ssl && $ssl_available) {
            my $s = IO::Socket::SSL->new(
                PeerAddr => $cur_host, PeerPort => 443, Proto => 'tcp',
                Timeout => $opt{T}, SSL_verify_mode => 0, SSL_hostname => $cur_hdr);
            if ($s) {
                print $s "HEAD $path HTTP/1.1\r\nHost: $cur_hdr\r\nConnection: close\r\n\r\n";
                $resp = _ssl_read($s); close $s;
            }
        } else {
            my $s = IO::Socket::INET->new(
                PeerAddr => $cur_host, PeerPort => $cur_port,
                Proto => 'tcp', Timeout => $opt{T});
            if ($s) {
                print $s "HEAD $path HTTP/1.1\r\nHost: $cur_hdr\r\nConnection: close\r\n\r\n";
                sleep(1); sysread($s, $resp, 4096); close $s;
            }
        }
        last unless $resp;

        my ($status) = $resp =~ /^HTTP\/\S+\s+(\d+)/;
        my ($loc)    = $resp =~ /^Location:\s*(\S+)/im;
        my $proto    = $use_ssl ? 'https' : 'http';
        push @chain, { hop => $hop, code => $status // '?',
                       url => "$proto://$cur_hdr$path" };

        last unless $loc && ($status // 0) =~ /^30[1237]/;
        chomp $loc;

        if ($loc =~ m{^(https?)://([^/?#]+)(/[^?#]*)?}) {
            $use_ssl  = ($1 eq 'https') ? 1 : 0;
            $cur_hdr  = $2;
            $path     = $3 // '/';
            $cur_port = $use_ssl ? 443 : 80;
            my $h = gethost($cur_hdr);
            $cur_host = $h ? inet_ntoa($h->addr_list->[0]) : $cur_hdr;
        } else {
            $path = $loc;  # relative redirect
        }
    }

    for my $step (@chain) {
        log_print("  $step->{hop}. [$step->{code}]  $step->{url}\n", 'c');
    }
    if (@chain) {
        my $final = $chain[-1]{url};
        if ($final =~ m{^https://}) {
            log_print("[OK] Final destination uses HTTPS\n\n", 'c');
        } else {
            log_print("[!]  Final destination is plain HTTP!\n\n", 'c');
        }
    }
}

# --------------------------------------------------------------------------
# CMS Detection (new in v3)
# --------------------------------------------------------------------------
sub cms_detect {
    log_print("CMS / Framework Detection\n", 'h');
    log_print("-------------------------\n", 'h');

    my $host_hdr = $host_resolves ? $host : $target;
    my $resp = _fetch_page($host_hdr, '/');
    return unless $resp;

    my ($hdrs, $body) = split(/\r?\n\r?\n/, $resp, 2);
    $hdrs //= ''; $body //= '';
    my @found;

    # WordPress
    if ($body  =~ m{/wp-content/|/wp-includes/}i ||
        $hdrs  =~ /X-Powered-By:.*WordPress/i    ||
        $body  =~ /<meta[^>]+WordPress/i) {
        my ($ver) = $body =~ /WordPress\s+([\d.]+)/i;
        push @found, "WordPress" . ($ver ? " $ver" : '');
    }
    # Joomla
    push @found, "Joomla"    if $body =~ m{/components/com_|Joomla!}i
                             || $hdrs =~ /X-Content-Encoded-By:.*Joomla/i;
    # Drupal
    if ($hdrs =~ /X-Generator:\s*(Drupal[^\r\n]*)/i ||
        $hdrs =~ /X-Drupal-Cache/i ||
        $body =~ m{/sites/default/files/|Drupal\.settings}i) {
        my ($ver) = $hdrs =~ /X-Generator:\s*Drupal\s*([\d.]+)/i;
        push @found, "Drupal" . ($ver ? " $ver" : '');
    }
    # Typo3
    push @found, "TYPO3"     if $body =~ m{typo3/|TYPO3 CMS}i;
    # Shopware
    push @found, "Shopware"  if $body =~ /shopware/i || $hdrs =~ /x-shopware/i;
    # Magento
    push @found, "Magento"   if $body =~ m{Mage\.Cookies|/skin/frontend/}i;
    # WooCommerce
    push @found, "WooCommerce" if $body =~ m{/woocommerce/|wc-ajax}i;
    # Laravel
    push @found, "Laravel"   if $hdrs =~ /laravel_session|XSRF-TOKEN/i
                             || $body =~ /Laravel/i;
    # Symfony
    push @found, "Symfony"   if $body =~ /Symfony/i || $hdrs =~ /symfony/i;
    # Django
    push @found, "Django"    if $body =~ /csrfmiddlewaretoken/i;
    # Ruby on Rails
    push @found, "Rails"     if $body =~ /csrf-token.*Rails|data-turbo/i;
    # Next.js
    push @found, "Next.js"   if $body =~ m{__NEXT_DATA__|/_next/static/}i;
    # Nuxt.js
    push @found, "Nuxt.js"   if $body =~ m{__NUXT__|/_nuxt/}i;
    # Ghost
    push @found, "Ghost CMS" if $body =~ m{/ghost/|content="Ghost}i;
    # Shopify
    push @found, "Shopify"   if $body =~ /Shopify\.theme|cdn\.shopify\.com/i;

    # Generator meta tag
    if ($body =~ /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)/i ||
        $body =~ /<meta[^>]+content=["']([^"']+)["'][^>]+name=["']generator/i) {
        push @found, "Generator: $1" unless grep { /\Q$1\E/i } @found;
    }

    if (@found) {
        log_print("Detected: " . join(', ', @found) . "\n\n", 'c');
        $json_results{cms} = \@found;
    } else {
        log_print("No CMS/framework identified\n\n", 'i');
    }
}

# --------------------------------------------------------------------------
# Technology Stack Fingerprint (new in v3)
# --------------------------------------------------------------------------
sub tech_stack_print {
    log_print("Technology Stack\n", 'h');
    log_print("----------------\n", 'h');

    my $host_hdr = $host_resolves ? $host : $target;
    my $resp = _fetch_page($host_hdr, '/');
    return unless $resp;

    my ($hdrs) = split(/\r?\n\r?\n/, $resp, 2);
    $hdrs //= '';
    my @stack;

    # Runtime/framework headers
    push @stack, "ASP.NET $1"    if $hdrs =~ /X-AspNet-Version:\s*([\S]+)/i;
    push @stack, "ASP.NET MVC"   if $hdrs =~ /X-AspNetMvc-Version/i;
    push @stack, "PHP"           if $hdrs =~ /X-Powered-By:\s*PHP\/([\S]+)/i
                                 && do { push @stack, "PHP $1" if $hdrs =~ /PHP\/([\S]+)/i; 0 };
    push @stack, "PHP"           if $hdrs =~ /X-Powered-By:\s*PHP/i && !grep{/PHP/}@stack;

    # Cookies
    while ($hdrs =~ /Set-Cookie:\s*([^\r\n]+)/gi) {
        my $c = $1;
        push @stack, "PHP session"        if $c =~ /PHPSESSID/i    && !grep{/PHP/}@stack;
        push @stack, "Java session"       if $c =~ /JSESSIONID/i;
        push @stack, "ASP.NET session"    if $c =~ /ASP\.NET_SessionId/i && !grep{/ASP/}@stack;
        push @stack, "ColdFusion"         if $c =~ /CFID|CFTOKEN/i;
    }

    # CDN / proxy
    push @stack, "Cloudflare CDN"  if $hdrs =~ /CF-RAY|cf-cache-status/i;
    push @stack, "Fastly CDN"      if $hdrs =~ /X-Fastly-Request-ID/i;
    push @stack, "Varnish Cache"   if $hdrs =~ /X-Varnish|Via:.*varnish/i;
    push @stack, "Akamai CDN"      if $hdrs =~ /X-Akamai|Akamai/i;
    push @stack, "Sucuri WAF"      if $hdrs =~ /X-Sucuri/i;
    push @stack, "Incapsula WAF"   if $hdrs =~ /X-Iinfo|incap_ses/i;

    # Web server
    if ($hdrs =~ /Server:\s*([^\r\n]+)/i) {
        push @stack, "Server: $1";
    }

    if (@stack) {
        log_print("$_\n", 'c') for @stack;
        log_print("\n", 'c');
        $json_results{tech_stack} = \@stack;
    } else {
        log_print("No additional stack info\n\n", 'i');
    }
}

# --------------------------------------------------------------------------
# Error Page Fingerprinting (new in v3)
# --------------------------------------------------------------------------
sub error_page_fingerprint {
    log_print("Error Page Fingerprint\n", 'h');
    log_print("----------------------\n", 'h');

    my $host_hdr = $host_resolves ? $host : $target;
    my $probe    = '/hackbot-probe-' . int(rand 999999);
    my $resp     = _fetch_page($host_hdr, $probe);
    return unless $resp;

    my ($hdrs, $body) = split(/\r?\n\r?\n/, $resp, 2);
    my ($code) = ($hdrs // '') =~ /^HTTP\/\S+\s+(\d+)/;
    $body //= '';

    return if !$code || $code == 200;  # custom 200-for-everything = no info

    my @hints;
    push @hints, "Apache"            if $body =~ /Apache.*Server at|Apache\/[\d.]/i;
    push @hints, "nginx"             if $body =~ /nginx\/[\d.]+|<hr>.*nginx/i;
    push @hints, "IIS"               if $body =~ /Internet Information Services|iis\/[\d.]/i;
    push @hints, "Tomcat"            if $body =~ /Apache Tomcat|Coyote/i;
    push @hints, "Django"            if $body =~ /Django Debug|Page not found.*Django/i;
    push @hints, "Laravel"           if $body =~ /Whoops!|laravel/i;
    push @hints, "Ruby on Rails"     if $body =~ /Routing Error|ActionController/i;
    push @hints, "Express/Node.js"   if $body =~ /Cannot GET|Express/i;
    push @hints, "Spring Boot/Java"  if $body =~ /Whitelabel Error|Spring Boot/i;
    push @hints, "Symfony"           if $body =~ /Symfony.*Exception/i;
    push @hints, "FastAPI/Python"    if $body =~ /Not Found.*detail|FastAPI/i;
    push @hints, "Werkzeug/Flask"    if $body =~ /Werkzeug|werkzeug/i;

    log_print("HTTP $code on unknown path\n", 'c');
    if (@hints) {
        log_print("Framework hints: " . join(', ', @hints) . "\n\n", 'c');
    } else {
        log_print("No framework identified from error page\n\n", 'i');
    }
}

# --------------------------------------------------------------------------
# Mixed Content Detection (new in v3)
# --------------------------------------------------------------------------
sub mixed_content_check {
    return unless $ssl_available;

    log_print("Mixed Content Check\n", 'h');
    log_print("-------------------\n", 'h');

    my $host_hdr = $host_resolves ? $host : $target;
    my $sock = IO::Socket::SSL->new(
        PeerAddr => $target, PeerPort => 443, Proto => 'tcp',
        Timeout => $opt{T}, SSL_verify_mode => 0, SSL_hostname => $host_hdr,
        SSL_alpn_protocols => ['http/1.1'],
    );

    if (!$sock) {
        log_print("HTTPS not available, skipping\n\n", 'i');
        return;
    }

    print $sock "GET / HTTP/1.1\r\nHost: $host_hdr\r\nConnection: close\r\n\r\n";
    my $resp = _ssl_read($sock);
    close $sock;
    return unless $resp;

    my (undef, $body) = split(/\r?\n\r?\n/, $resp, 2);
    return unless $body;

    my @mixed;
    while ($body =~ /(?:src|href|action|data-src|data-href)=["'](http:\/\/[^"'\s>]+)/gi) {
        push @mixed, $1 unless grep { $_ eq $1 } @mixed;
        last if @mixed >= 10;
    }

    if (@mixed) {
        log_print("[!] " . scalar(@mixed) . " mixed content reference(s) found:\n", 'c');
        log_print("    $_\n", 'c') for @mixed;
        log_print("\n", 'c');
        $json_results{mixed_content} = \@mixed;
    } else {
        log_print("[OK] No mixed content detected\n\n", 'c');
    }
}

# --------------------------------------------------------------------------
# HTTP Security Headers (new in v3)
# --------------------------------------------------------------------------
sub security_headers {
    log_print("HTTP Security Headers\n", 'h');
    log_print("---------------------\n", 'h');

    my $host_hdr = $host_resolves ? $host : $target;
    my ($resp, $checked_via);

    # Try HTTPS first (correct place for security headers)
    if ($ssl_available) {
        my $ssl_sock = IO::Socket::SSL->new(
            PeerAddr        => $target, PeerPort => 443,
            Proto           => 'tcp', Timeout => $opt{T},
            SSL_verify_mode => 0,
            SSL_hostname    => $host_hdr,
        );
        if ($ssl_sock) {
            print $ssl_sock "GET / HTTP/1.1\r\nHost: $host_hdr\r\nConnection: close\r\n\r\n";
            $resp = _ssl_read($ssl_sock);
            close $ssl_sock;
            $checked_via = 'HTTPS port 443' if $resp;
        }
    }

    # Fall back to HTTP on configured port (always port 80, not 443)
    unless ($resp) {
        my $sock = IO::Socket::INET->new(
            PeerAddr => $target, PeerPort => $port,
            Proto => 'tcp', Timeout => $opt{T},
        );
        return unless $sock;
        print $sock "GET / HTTP/1.1\r\nHost: $host_hdr\r\nConnection: close\r\n\r\n";
        sleep(2);
        sysread($sock, $resp, 16384);
        close $sock;
        $checked_via = "HTTP port $port" if $resp;
    }
    return unless $resp;

    # Only parse the response header block
    my ($header_block) = split(/\r?\n\r?\n/, $resp, 2);
    $header_block //= $resp;

    log_print("(via $checked_via)\n", 'i');

    my @hdrs = (
        ['Strict-Transport-Security', 'HSTS missing - HTTPS not enforced'],
        ['Content-Security-Policy',   'CSP missing - XSS risk'],
        ['X-Frame-Options',           'Clickjacking protection missing'],
        ['X-Content-Type-Options',    'MIME sniffing protection missing'],
        ['Referrer-Policy',           'Referrer policy not set'],
        ['Permissions-Policy',        'Permissions policy not set'],
    );

    for my $hdr (@hdrs) {
        my ($name, $warn) = @$hdr;
        if ($header_block =~ /^\Q$name\E:\s*(.+?)\r?$/im) {
            log_print("[OK] $name: $1\n", 'c');
        } else {
            log_print("[!]  $warn\n", 'c');
        }
    }
    log_print("\n", 'c');
}

# --------------------------------------------------------------------------
# Cookie Security Flags (new in v3)
# --------------------------------------------------------------------------
sub cookie_check {
    log_print("Cookie Security Flags\n", 'h');
    log_print("---------------------\n", 'h');

    my $host_hdr = $host_resolves ? $host : $target;
    my $resp = _fetch_page($host_hdr);
    return unless $resp;

    my @cookies = ($resp =~ /^Set-Cookie:\s*(.+)$/gim);
    unless (@cookies) {
        log_print("No Set-Cookie headers found\n\n", 'i');
        return;
    }

    for my $cookie (@cookies) {
        my ($name) = $cookie =~ /^([^=;,\s]+)/;
        $name //= 'unknown';
        my @issues;

        push @issues, "Secure missing"       unless $cookie =~ /;\s*Secure\b/i;
        push @issues, "HttpOnly missing"     unless $cookie =~ /;\s*HttpOnly\b/i;

        if    ($cookie =~ /;\s*SameSite=None/i)   { push @issues, "SameSite=None (CSRF risk)" }
        elsif ($cookie !~ /;\s*SameSite=/i)        { push @issues, "SameSite missing" }

        if (@issues) {
            log_print("[!] $name: " . join(' | ', @issues) . "\n", 'c');
        } else {
            log_print("[OK] $name: Secure + HttpOnly + SameSite set\n", 'c');
        }
    }
    log_print("\n", 'c');
}

# --------------------------------------------------------------------------
# CORS Misconfiguration Check (new in v3)
# --------------------------------------------------------------------------
sub cors_check {
    log_print("CORS Policy\n", 'h');
    log_print("-----------\n", 'h');

    my $host_hdr   = $host_resolves ? $host : $target;
    my $evil_origin = 'https://hackbot-cors-test.evil.example';

    # Test endpoints: root + /api
    for my $path ('/', '/api', '/api/v1') {
        my $resp = _fetch_page($host_hdr, $path, "Origin: $evil_origin\r\n");
        next unless $resp;

        my ($acao) = $resp =~ /^Access-Control-Allow-Origin:\s*(.+)$/im;
        next unless $acao;
        chomp $acao; $acao =~ s/\s+$//;

        my ($acac) = $resp =~ /^Access-Control-Allow-Credentials:\s*(.+)$/im;
        my $creds = ($acac // '') =~ /true/i;

        my $label = $path eq '/' ? 'root' : $path;

        if ($acao eq '*' && $creds) {
            log_print("[CRITICAL] $label: ACAO=* with Credentials=true — browsers block but server is misconfigured!\n", 'c');
        } elsif ($acao eq '*') {
            log_print("[!] $label: ACAO=* — any origin allowed (acceptable for public APIs)\n", 'c');
        } elsif (index(lc $acao, 'evil.example') >= 0) {
            if ($creds) {
                log_print("[CRITICAL] $label: reflects arbitrary Origin + Credentials=true — session hijacking possible!\n", 'c');
            } else {
                log_print("[HIGH] $label: reflects arbitrary Origin — $acao\n", 'c');
            }
        } else {
            log_print("[OK] $label: ACAO=$acao" . ($creds ? " (Credentials=true)" : "") . "\n", 'c');
        }
    }
    log_print("\n", 'c');
}

# Shared helper: fetch a page via HTTPS (preferred) or HTTP, with optional extra headers
sub _fetch_page {
    my ($host_hdr, $path, $extra_headers) = @_;
    $path //= '/';
    $extra_headers //= '';
    my $resp;

    my $used_https = 0;
    if ($ssl_available) {
        my $s = IO::Socket::SSL->new(
            PeerAddr => $target, PeerPort => 443, Proto => 'tcp',
            Timeout => $opt{T}, SSL_verify_mode => 0, SSL_hostname => $host_hdr,
        );
        if ($s) {
            print $s "GET $path HTTP/1.1\r\nHost: $host_hdr\r\n${extra_headers}Connection: close\r\n\r\n";
            $resp = _ssl_read($s);
            close $s;
            $used_https = 1 if $resp;
        }
    }
    unless ($resp) {
        log_print("(HTTPS not available, checking HTTP port $port)\n", 'i');
        my $s = IO::Socket::INET->new(
            PeerAddr => $target, PeerPort => $port, Proto => 'tcp', Timeout => $opt{T});
        return undef unless $s;
        print $s "GET $path HTTP/1.1\r\nHost: $host_hdr\r\n${extra_headers}Connection: close\r\n\r\n";
        sleep(1); sysread($s, $resp, 16384); close $s;
    }
    return $resp;
}

# --------------------------------------------------------------------------
# HTTPS / TLS scan (new in v3)
# --------------------------------------------------------------------------
sub https_scan {
    log_print("HTTPS / TLS scan (port 443)\n", 'h');
    log_print("---------------------------\n", 'h');

    unless ($ssl_available) {
        log_print("IO::Socket::SSL not installed - install with: cpan IO::Socket::SSL\n\n", 'i');
        return;
    }

    my $host_hdr = $host_resolves ? $host : $target;
    my $sock = IO::Socket::SSL->new(
        PeerAddr        => $target,
        PeerPort        => 443,
        Proto           => 'tcp',
        Timeout         => $opt{T},
        SSL_verify_mode => 0,
        SSL_hostname    => $host_hdr,
        SSL_alpn_protocols => ['h2', 'http/1.1'],
    );

    if (!$sock) {
        log_print("No HTTPS on port 443\n\n", 'i');
        return;
    }

    my $tls_ver  = $sock->get_sslversion();
    my $cipher   = $sock->get_cipher();
    my $cert_cn  = $sock->peer_certificate('cn')      // 'n/a';
    my $issuer   = $sock->peer_certificate('issuer')  // '';
    my $subject  = $sock->peer_certificate('subject') // '';
    my $not_after  = eval { $sock->peer_certificate('not_after')  } // '';
    my $not_before = eval { $sock->peer_certificate('not_before') } // '';

    # HTTP/2 detection via ALPN
    my $alpn = eval { $sock->alpn_selected() } // 'http/1.1';
    my $http_ver = ($alpn eq 'h2') ? 'HTTP/2' : 'HTTP/1.1';

    log_print("TLS version:  $tls_ver\n", 'c');
    log_print("HTTP version: $http_ver\n", 'c');
    log_print("Cipher suite: $cipher\n", 'c');
    log_print("Certificate:  $cert_cn\n", 'c');

    # Issuer / self-signed detection
    if ($issuer) {
        my ($issuer_cn) = $issuer =~ /CN=([^,\/]+)/;
        log_print("Issuer:       " . ($issuer_cn // $issuer) . "\n", 'c');
        if ($subject && $issuer eq $subject) {
            log_print("[!] Self-signed certificate!\n", 'c');
        }
    }

    # Subject Alternative Names — returned as flat list (type, value, type, value, ...)
    my @sans_flat = eval { $sock->peer_certificate('subjectAltNames') };
    if (@sans_flat) {
        my @dns_sans;
        for (my $i = 0; $i < $#sans_flat; $i += 2) {
            push @dns_sans, $sans_flat[$i+1] if $sans_flat[$i] == 2;
        }
        log_print("SANs:         " . join(', ', @dns_sans) . "\n", 'c') if @dns_sans;
    }

    # Certificate expiry
    if ($not_after) {
        log_print("Valid until:  $not_after\n", 'c');
        my $days = _cert_days_remaining($not_after);
        if    (!defined $days)  { }
        elsif ($days < 0)       { log_print("[CRITICAL] Certificate EXPIRED " . abs($days) . " days ago!\n", 'c') }
        elsif ($days < 14)      { log_print("[CRITICAL] Certificate expires in $days days!\n", 'c') }
        elsif ($days < 30)      { log_print("[HIGH] Certificate expires in $days days!\n", 'c') }
        elsif ($days < 90)      { log_print("[!] Certificate expires in $days days\n", 'c') }
        else                    { log_print("[OK] $days days remaining\n", 'c') }
    }

    # TLS version warnings
    if ($tls_ver =~ /SSLv|TLSv1\.0|TLSv1\.1/) {
        log_print("[!] Deprecated TLS version ($tls_ver) - TLS 1.2+ required!\n", 'c');
    } elsif ($tls_ver =~ /TLSv1_3|TLSv1\.3/) {
        log_print("[OK] TLS 1.3\n", 'c');
    } elsif ($tls_ver =~ /TLSv1_2|TLSv1\.2/) {
        log_print("[OK] TLS 1.2\n", 'c');
    }

    if ($cipher =~ /RC4|DES\b|NULL|EXPORT|MD5/i) {
        log_print("[!] Weak cipher suite ($cipher)\n", 'c');
    }

    print $sock "HEAD / HTTP/1.1\r\nHost: $host_hdr\r\nConnection: close\r\n\r\n";
    my $resp = _ssl_read($sock);
    close $sock;

    check_server_version($resp) if $resp;
    $json_results{tls} = { version => $tls_ver, cipher => $cipher, cn => $cert_cn };
    log_print("\n", 'c');
}

sub _cert_days_remaining {
    my ($date_str) = @_;
    # IO::Socket::SSL returns dates like "Apr 22 23:59:59 2026 GMT"
    # or in ASN1 format "20260422235959Z"
    my ($y, $mo, $d);
    if ($date_str =~ /(\d{4})(\d{2})(\d{2})/) {
        ($y, $mo, $d) = ($1, $2+0, $3+0);
    } elsif ($date_str =~ /(\w{3})\s+(\d+)\s+[\d:]+\s+(\d{4})/) {
        my %m = (Jan=>1,Feb=>2,Mar=>3,Apr=>4,May=>5,Jun=>6,
                 Jul=>7,Aug=>8,Sep=>9,Oct=>10,Nov=>11,Dec=>12);
        ($y, $mo, $d) = ($3+0, $m{$1}//0, $2+0);
    } else {
        return undef;
    }
    my @n = localtime;
    my ($ny, $nm, $nd) = ($n[5]+1900, $n[4]+1, $n[3]);
    return ($y-$ny)*365 + ($mo-$nm)*30 + ($d-$nd);
}

# --------------------------------------------------------------------------
# Email Security: SPF / DKIM / DMARC (new in v3)
# --------------------------------------------------------------------------
sub email_security {
    my $domain = _base_domain($host) || $host;
    return unless $domain;

    log_print("Email Security: $domain\n", 'h');
    log_print("-" x (16 + length $domain) . "\n", 'h');

    # --- SPF ---
    open(my $spf_fh, '-|', 'dig', '+short', 'TXT', $domain) or goto SKIP_SPF;
    my @spf_recs = grep { /v=spf1/i } <$spf_fh>;
    close $spf_fh;

    if (@spf_recs) {
        (my $spf = $spf_recs[0]) =~ s/"\s*"//g;
        $spf =~ s/^"|"$//g; chomp $spf;
        log_print("SPF:   $spf\n", 'c');
        if    ($spf =~ /\-all/) { log_print("       [OK] -all: unauthorized senders rejected\n", 'c') }
        elsif ($spf =~ /\~all/) { log_print("       [~]  ~all: soft fail, marked as spam\n", 'c') }
        elsif ($spf =~ /\?all|\+all/) { log_print("       [!]  +all/?all: allows spoofing!\n", 'c') }
    } else {
        log_print("SPF:   [!] No SPF record — domain can be spoofed!\n", 'c');
    }
    SKIP_SPF:

    # --- DMARC ---
    open(my $dm_fh, '-|', 'dig', '+short', 'TXT', "_dmarc.$domain") or goto SKIP_DMARC;
    my @dm_recs = grep { /v=DMARC1/i } <$dm_fh>;
    close $dm_fh;

    if (@dm_recs) {
        (my $dmarc = $dm_recs[0]) =~ s/"\s*"//g;
        $dmarc =~ s/^"|"$//g; chomp $dmarc;
        log_print("DMARC: $dmarc\n", 'c');
        if    ($dmarc =~ /p=reject/i)     { log_print("       [OK] p=reject: spoofed mail rejected\n", 'c') }
        elsif ($dmarc =~ /p=quarantine/i) { log_print("       [~]  p=quarantine: spoofed mail → spam\n", 'c') }
        elsif ($dmarc =~ /p=none/i)       { log_print("       [!]  p=none: monitoring only, no enforcement!\n", 'c') }
        if ($dmarc =~ /rua=([^;]+)/i)     { log_print("       Reports: $1\n", 'c') }
    } else {
        log_print("DMARC: [!] No DMARC record found!\n", 'c');
    }
    SKIP_DMARC:

    # --- DKIM — try common selectors ---
    my @selectors = qw(default google mail dkim k1 s1 s2
                       selector1 selector2 smtp mx email
                       dkim1 key1 key2 mimecast);
    log_print("DKIM:  Testing " . scalar(@selectors) . " common selectors...\n", 'h');
    my $dkim_found = 0;
    for my $sel (@selectors) {
        open(my $dk_fh, '-|', 'dig', '+short', 'TXT', "$sel._domainkey.$domain") or next;
        my @dk = grep { /v=DKIM1/i } <$dk_fh>;
        close $dk_fh;
        if (@dk) {
            my $rec = $dk[0]; chomp $rec; $rec =~ s/"\s*"//g; $rec =~ s/^"|"$//g;
            my $short = length($rec) > 80 ? substr($rec,0,80).'...' : $rec;
            log_print("DKIM:  [OK] selector '$sel': $short\n", 'c');
            $dkim_found++;
        }
    }
    log_print("DKIM:  [!] No DKIM records found for common selectors\n", 'c') unless $dkim_found;

    # --- MTA-STS (bonus) ---
    open(my $mta_fh, '-|', 'dig', '+short', 'TXT', "_mta-sts.$domain") or goto DONE_EMAIL;
    my @mta = grep { /v=STSv1/i } <$mta_fh>;
    close $mta_fh;
    if (@mta) {
        log_print("MTA-STS: [OK] configured\n", 'c');
    } else {
        log_print("MTA-STS: [i] not configured (optional but recommended)\n", 'i');
    }
    DONE_EMAIL:

    log_print("\n", 'c');
}

# --------------------------------------------------------------------------
# Geolocation via ip-api.com (new in v3)
# --------------------------------------------------------------------------
sub geolocation {
    return unless check_ip($target);

    log_print("Geolocation for $target\n", 'h');
    log_print("-----------------------\n", 'h');

    if (is_private_ip($target)) {
        log_print("Private/reserved address, skipping geolocation\n\n", 'i');
        return;
    }

    my $sock = IO::Socket::INET->new(
        PeerAddr => 'ip-api.com', PeerPort => 80,
        Proto => 'tcp', Timeout => $opt{T},
    );

    if (!$sock) {
        log_print("Cannot reach ip-api.com\n\n", 'i');
        return;
    }

    print $sock "GET /json/$target?fields=country,regionName,city,isp,org,as HTTP/1.0\r\n";
    print $sock "Host: ip-api.com\r\n\r\n";
    sleep(2);
    sysread($sock, my $resp, 4096);
    close $sock;

    my (undef, $body) = split(/\r?\n\r?\n/, $resp // '', 2);
    if ($body) {
        my $data = eval { JSON::PP::decode_json($body) } // {};
        log_print("Country: $data->{country}\n",    'c') if $data->{country};
        log_print("Region:  $data->{regionName}\n", 'c') if $data->{regionName};
        log_print("City:    $data->{city}\n",        'c') if $data->{city};
        log_print("ISP:     $data->{isp}\n",         'c') if $data->{isp};
        log_print("Org:     $data->{org}\n",         'c') if $data->{org};
        log_print("AS:      $data->{as}\n",          'c') if $data->{as};
        $json_results{geo} = $data;
    }
    log_print("\n", 'c');
}

# --------------------------------------------------------------------------
# Port scan (new in v3)
# Read from an SSL socket until the connection closes or timeout hits
sub _ssl_read {
    my ($sock) = @_;
    my $buf = '';
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm(8);
        my $chunk;
        while (sysread($sock, $chunk, 4096)) {
            $buf .= $chunk;
            last if length($buf) > 65536;
        }
        alarm(0);
    };
    return $buf;
}

# --------------------------------------------------------------------------
sub port_scan {
    log_print("Port scan\n", 'h');
    log_print("---------\n", 'h');

    my %services = (
        21 => 'ftp',         22 => 'ssh',          23 => 'telnet',
        25 => 'smtp',        53 => 'dns',           80 => 'http',
       110 => 'pop3',       111 => 'rpcbind',      139 => 'netbios',
       143 => 'imap',       443 => 'https',        445 => 'smb',
       993 => 'imaps',      995 => 'pop3s',       1433 => 'mssql',
      3000 => 'dev-webserver/ui',
      3306 => 'mysql',     3389 => 'rdp',         5173 => 'vite-devserver',
      5900 => 'vnc',       6379 => 'redis',        8000 => 'http-api-alt',
      8080 => 'http-gateway/web-interface',
      8443 => 'https-alt', 8888 => 'web-notebook-dev',
     18789 => 'openclaw-gateway',
     27017 => 'mongodb',
    );

    my @open_ports;
    for my $p (sort { $a <=> $b } keys %services) {
        my $sock = IO::Socket::INET->new(
            PeerAddr => $target, PeerPort => $p,
            Proto => 'tcp', Timeout => 2,
        );
        if ($sock) {
            log_print(sprintf("  %-6d open  %s\n", $p, $services{$p}), 'c');
            push @open_ports, $p;
            close $sock;
        }
    }
    log_print("No common ports open\n", 'i') unless @open_ports;
    log_print("\n", 'c');
    $json_results{open_ports} = \@open_ports;
}

# --------------------------------------------------------------------------
# OS Detection — HTTP headers + SSH/FTP banners + Nmap (new in v3)
# --------------------------------------------------------------------------
sub os_detect {
    log_print("OS Detection\n", 'h');
    log_print("------------\n", 'h');

    my @hints;

    # --- Source 1: SSH banner (already captured by ssh_scan) ---
    if (my $ssh = $json_results{ssh}) {
        push @hints, _os_from_ssh($ssh);
    }

    # --- Source 2: HTTP Server header (already captured by checkweb) ---
    if (my $srv = $json_results{server}) {
        push @hints, _os_from_http_server($srv);
    }

    # --- Source 3: FTP banner ---
    push @hints, _os_from_ftp();

    # --- Source 4: Live HTTP header fetch (if web not yet scanned) ---
    unless ($json_results{server}) {
        push @hints, _os_from_http_live();
    }

    # --- Source 5: Ping TTL (no root, no nmap needed) ---
    push @hints, _os_from_ping_ttl();

    # --- Source 6: Port combination inference ---
    push @hints, _os_from_open_ports();

    # --- Source 7: SMTP/POP3/IMAP banners ---
    push @hints, _os_from_mail_banners();

    # --- Source 8: Nmap OS detection (optional, best results with root) ---
    push @hints, _os_from_nmap();

    # Deduplicate and report
    my %seen;
    my @unique = grep { $_ && !$seen{$_}++ } @hints;

    if (@unique) {
        log_print("$_\n", 'c') for @unique;
        $json_results{os_hints} = \@unique;
    } else {
        log_print("No OS indicators found\n", 'i');
    }
    log_print("\n", 'c');
}

sub _os_from_ssh {
    my ($banner) = @_;
    my @h;
    # OpenSSH distro patches embed OS name: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.15
    push @h, "Linux (Ubuntu)"       if $banner =~ /Ubuntu[_-]/i;
    push @h, "Linux (Debian)"       if $banner =~ /Debian[_-]/i;
    push @h, "Linux (CentOS)"       if $banner =~ /\bcentos\b/i;
    push @h, "Linux (RHEL/Fedora)"  if $banner =~ /\b(rhel|fedora|red.?hat)\b/i;
    push @h, "Linux (Alpine)"       if $banner =~ /Alpine/i;
    push @h, "FreeBSD"              if $banner =~ /FreeBSD/i;
    push @h, "OpenBSD"              if $banner =~ /OpenBSD/i;
    push @h, "macOS / Darwin"       if $banner =~ /Darwin/i;
    push @h, "Windows (OpenSSH)"    if $banner =~ /OpenSSH_for_Windows/i;
    push @h, "Cisco IOS"            if $banner =~ /Cisco/i;
    push @h, "Juniper JunOS"        if $banner =~ /Juniper|JunOS/i;

    # Version-based inference when no distro tag present
    if (!@h && $banner =~ /OpenSSH_([\d.]+)/i) {
        my $ver = $1;
        push @h, "OpenSSH $ver (version suggests: " . _ssh_ver_to_distro($ver) . ")"
            if _ssh_ver_to_distro($ver);
    }
    return map { "$_  [SSH banner]" } @h;
}

sub _ssh_ver_to_distro {
    my ($v) = @_;
    return 'RHEL/CentOS 7'  if $v =~ /^7\.4/;
    return 'RHEL/CentOS 8'  if $v =~ /^8\.0/;
    return 'Debian 10'      if $v =~ /^7\.9/;
    return 'Debian 11'      if $v =~ /^8\.4/;
    return 'Ubuntu 20.04'   if $v =~ /^8\.2/;
    return 'Ubuntu 22.04'   if $v =~ /^8\.9/;
    return 'Ubuntu 24.04'   if $v =~ /^9\.[36]/;
    return '';
}

sub _os_from_http_server {
    my ($srv) = @_;
    my @h;
    # Apache often includes distro in parens: Apache/2.4.41 (Ubuntu)
    push @h, "Linux (Ubuntu)"    if $srv =~ /\(Ubuntu\)/i;
    push @h, "Linux (Debian)"    if $srv =~ /\(Debian\)/i;
    push @h, "Linux (CentOS)"    if $srv =~ /\(CentOS\)/i;
    push @h, "Linux (RHEL)"      if $srv =~ /\(Red.?Hat\)/i;
    push @h, "Linux (Fedora)"    if $srv =~ /\(Fedora\)/i;
    push @h, "Linux (Amazon)"    if $srv =~ /\(Amazon\)/i;
    push @h, "Windows Server"    if $srv =~ /Microsoft-IIS|Win(?:32|64|dows)/i;
    push @h, "FreeBSD"           if $srv =~ /\(FreeBSD\)/i;
    push @h, "macOS / Darwin"    if $srv =~ /Darwin/i;
    # Cloudflare / CDN hides origin
    push @h, "Origin hidden by Cloudflare CDN" if $srv =~ /cloudflare/i;
    push @h, "Origin hidden by CDN"             if $srv =~ /\b(akamai|fastly|varnish)\b/i;
    return map { "$_  [HTTP Server header]" } @h;
}

sub _os_from_http_live {
    my $host_hdr = $host_resolves ? $host : $target;
    my $resp;

    if ($ssl_available) {
        my $s = IO::Socket::SSL->new(
            PeerAddr => $target, PeerPort => 443, Proto => 'tcp',
            Timeout => $opt{T}, SSL_verify_mode => 0, SSL_hostname => $host_hdr,
        );
        if ($s) {
            print $s "HEAD / HTTP/1.1\r\nHost: $host_hdr\r\nConnection: close\r\n\r\n";
            $resp = _ssl_read($s); close $s;
        }
    }
    unless ($resp) {
        my $s = IO::Socket::INET->new(
            PeerAddr => $target, PeerPort => $port, Proto => 'tcp', Timeout => $opt{T});
        return () unless $s;
        print $s "HEAD / HTTP/1.1\r\nHost: $host_hdr\r\nConnection: close\r\n\r\n";
        sleep(1); sysread($s, $resp, 4096); close $s;
    }
    return () unless $resp;

    my @h;
    push @h, _os_from_http_server($1)      if $resp =~ /^Server:\s*(.+)/im;
    push @h, "Windows/.NET  [X-Powered-By]" if $resp =~ /^X-Powered-By:.*ASP\.NET/im;
    push @h, "PHP app  [X-Powered-By]"      if $resp =~ /^X-Powered-By:\s*PHP/im;
    push @h, "Java/Servlet  [X-Powered-By]" if $resp =~ /^X-Powered-By:.*servlet|JSP/im;
    return @h;
}

sub _os_from_ftp {
    # FTP banner sometimes reveals OS
    my $sock = IO::Socket::INET->new(
        PeerAddr => $target, PeerPort => 21, Proto => 'tcp', Timeout => $opt{T});
    return () unless $sock;
    sysread($sock, my $banner, 256);
    close $sock;
    return () unless $banner;
    my @h;
    push @h, "Linux (Ubuntu)  [FTP banner]"  if $banner =~ /Ubuntu/i;
    push @h, "Linux (Debian)  [FTP banner]"  if $banner =~ /Debian/i;
    push @h, "Windows  [FTP banner]"         if $banner =~ /Windows|IIS/i;
    push @h, "Cisco IOS  [FTP banner]"       if $banner =~ /Cisco/i;
    push @h, "ProFTPD  [FTP banner]"         if $banner =~ /ProFTPD/i;
    push @h, "vsftpd  [FTP banner]"          if $banner =~ /vsftpd/i;
    push @h, "Pure-FTPd  [FTP banner]"       if $banner =~ /Pure-FTPd/i;
    return @h;
}

sub _os_from_ping_ttl {
    # TTL in ICMP replies reveals the original OS TTL value:
    # Linux/Unix = 64, Windows = 128, Cisco/Solaris = 255
    open(my $p, '-|', 'ping', '-c', '1', '-W', '3', $target) or return ();
    my $out = do { local $/; <$p> };
    close $p;
    return () unless $out;

    my ($ttl) = $out =~ /ttl[=:](\d+)/i;
    return () unless $ttl;

    # Infer original TTL by rounding up to nearest standard value
    my $orig = $ttl > 192 ? 255
             : $ttl >  96 ? 128
             :               64;
    my $hops = $orig - $ttl;

    my $guess = $orig == 255 ? 'Cisco / Solaris / network device'
              : $orig == 128 ? 'Windows'
              :                'Linux / Unix / macOS';

    return "$guess  [ping TTL=$ttl, orig=$orig, ~$hops hops]";
}

sub _os_from_open_ports {
    my @open = @{ $json_results{open_ports} // [] };
    return () unless @open;

    my %p = map { $_ => 1 } @open;
    my @h;

    # Strong Windows indicators
    if ($p{3389}) {
        push @h, "Windows  [RDP port 3389 open]";
    }
    if ($p{445} || $p{139}) {
        push @h, "Windows  [SMB/NetBIOS ports open]";
    }
    if ($p{1433}) {
        push @h, "Windows (likely)  [MSSQL port 1433 open]";
    }

    # Strong Linux indicators
    if ($p{22} && !$p{3389} && !$p{445}) {
        push @h, "Linux / Unix (likely)  [SSH open, no Windows-specific ports]";
    }

    # Mail server stack → likely Linux
    my $mail_ports = grep { $p{$_} } (25, 110, 143, 993, 995);
    if ($mail_ports >= 3 && !$p{3389}) {
        push @h, "Linux mail server (likely)  [multiple mail ports open]";
    }

    # Database exposure hints
    push @h, "MySQL server exposed  [port 3306 open]"  if $p{3306};
    push @h, "Redis exposed  [port 6379 open]"         if $p{6379};
    push @h, "MongoDB exposed  [port 27017 open]"      if $p{27017};

    return @h;
}

sub _os_from_mail_banners {
    my @h;
    # SMTP
    {
        my $s = IO::Socket::INET->new(
            PeerAddr => $target, PeerPort => 25,
            Proto => 'tcp', Timeout => $opt{T});
        if ($s) {
            sysread($s, my $b, 256); close $s;
            push @h, "Linux (Postfix)   [SMTP banner]" if ($b // '') =~ /Postfix/i;
            push @h, "Linux (Exim)      [SMTP banner]" if ($b // '') =~ /Exim/i;
            push @h, "Linux (Sendmail)  [SMTP banner]" if ($b // '') =~ /Sendmail/i;
            push @h, "Windows (Exchange) [SMTP banner]" if ($b // '') =~ /Exchange|Microsoft/i;
            push @h, "Dovecot MTA       [SMTP banner]" if ($b // '') =~ /Dovecot/i;
        }
    }
    # POP3
    {
        my $s = IO::Socket::INET->new(
            PeerAddr => $target, PeerPort => 110,
            Proto => 'tcp', Timeout => $opt{T});
        if ($s) {
            sysread($s, my $b, 256); close $s;
            push @h, "Dovecot (Linux)  [POP3 banner]"  if ($b // '') =~ /Dovecot/i;
            push @h, "Courier (Linux)  [POP3 banner]"  if ($b // '') =~ /Courier/i;
            push @h, "Windows Exchange [POP3 banner]"   if ($b // '') =~ /Exchange|Microsoft/i;
        }
    }
    return @h;
}

sub _os_from_nmap {
    # nmap -O needs root; -sV works without
    my $nmap;
    {
        open(my $w, '-|', 'which', 'nmap') or return ();
        $nmap = do { local $/; <$w> };
        chomp $nmap if defined $nmap;
        $nmap //= '';
    }
    unless ($nmap && -x $nmap) {
        log_print("Nmap not installed - skipping TCP/IP stack fingerprint\n", 'i');
        log_print("  Install: sudo apt install nmap   (Debian/Ubuntu/Raspberry Pi OS)\n", 'i');
        log_print("  For full OS detection run as root: sudo perl hackbot2 -n <host>\n", 'i');
        return ();
    }

    my $is_root = ($> == 0);
    my @cmd = ($nmap, '-T4', '--open', '-p', '22,25,80,443,445,3306,3389');

    if ($is_root) {
        push @cmd, '-O', '--osscan-guess';
        log_print("Running nmap OS scan (root)...\n", 'h');
    } else {
        push @cmd, '-sV', '--version-intensity', '5';
        log_print("Running nmap -sV (install nmap + run as root for full -O OS detection)...\n", 'h');
    }
    push @cmd, $target;

    open(my $nm, '-|', @cmd) or return ();
    my $out = do { local $/; <$nm> };
    close $nm;
    return () unless $out;

    my @h;

    # OS detection results (root mode)
    if ($out =~ /OS details?:\s*(.+)/i) {
        push @h, "Nmap OS: $1";
    } elsif ($out =~ /Running(?:\s+\(JUST GUESSING\))?:\s*(.+)/i) {
        push @h, "Nmap guess: $1";
    }

    # Version scan: extract OS hints from service versions
    while ($out =~ /(\d+\/tcp\s+open\s+\S+\s+.+)/g) {
        my $line = $1;
        push @h, "Windows (RDP open)  [nmap]"       if $line =~ /3389.*open/;
        push @h, "Windows (SMB open)  [nmap]"       if $line =~ /445.*open/;
        push @h, "Linux (MySQL $1)  [nmap]"         if $line =~ /mysql.*?(\d+\.\d+)/i;
        if ($line =~ /ssh.*OpenSSH_([\d.]+).*?(Ubuntu|Debian|CentOS|RHEL|Fedora)/i) {
            push @h, "Linux ($2, OpenSSH $1)  [nmap]";
        }
    }

    # CPE-based OS
    if ($out =~ /OS CPE:\s*(.+)/i) {
        my $cpe = $1;
        push @h, "Windows  [nmap CPE]" if $cpe =~ /windows/i;
        push @h, "Linux    [nmap CPE]" if $cpe =~ /linux/i;
        push @h, "Cisco    [nmap CPE]" if $cpe =~ /cisco/i;
    }

    return @h;
}

# --------------------------------------------------------------------------
# Service Banner Grabbing (new in v3)
# --------------------------------------------------------------------------
sub service_banners {
    log_print("Service Banner Scan\n", 'h');
    log_print("-------------------\n", 'h');

    # Plain-text banner services: just connect and read
    my %plain = (
        110  => 'POP3',
        143  => 'IMAP',
        587  => 'SMTP-Submission',
        6379 => 'Redis',
        11211 => 'Memcached',
    );

    for my $p (sort { $a <=> $b } keys %plain) {
        my $sock = IO::Socket::INET->new(
            PeerAddr => $target, PeerPort => $p,
            Proto => 'tcp', Timeout => $opt{T});
        next unless $sock;
        my $banner = '';
        eval {
            local $SIG{ALRM} = sub { die "timeout\n" };
            alarm($opt{T} + 2);
            if ($p == 6379) {
                print $sock "INFO server\r\n";
                sleep(1);
            }
            if ($p == 11211) {
                print $sock "stats\r\n";
                sleep(1);
            }
            sysread($sock, $banner, 512);
            alarm(0);
        };
        close $sock;
        next unless $banner =~ /\S/;

        my $clean = _banner_first_line($banner);

        # Redis: extract version
        if ($p == 6379 && $banner =~ /redis_version:([\d.]+)/i) {
            log_print("Redis     (6379): v$1", 'c');
            log_print(" — no auth required!\n", 'c') if $banner =~ /requirepass/i == 0;
            log_print("\n", 'c');
        }
        # Memcached: extract version
        elsif ($p == 11211 && $banner =~ /STAT version ([\d.]+)/i) {
            log_print("Memcached (11211): v$1 — no auth, open!\n\n", 'c');
        }
        else {
            log_print(sprintf("%-10s(%5d): %s\n\n", $plain{$p}, $p, $clean), 'c');
        }
    }

    # SSL banner services
    if ($ssl_available) {
        for my $p (993, 995) {
            my $name = $p == 993 ? 'IMAPS' : 'POP3S';
            my $sock = IO::Socket::SSL->new(
                PeerAddr => $target, PeerPort => $p, Proto => 'tcp',
                Timeout => $opt{T}, SSL_verify_mode => 0);
            next unless $sock;
            sysread($sock, my $banner, 256);
            close $sock;
            next unless $banner && $banner =~ /\S/;
            log_print(sprintf("%-10s(%5d): %s\n\n", $name, $p, _banner_first_line($banner)), 'c');
        }
    }

    # MySQL: version is in the initial handshake packet
    {
        my $sock = IO::Socket::INET->new(
            PeerAddr => $target, PeerPort => 3306,
            Proto => 'tcp', Timeout => $opt{T});
        if ($sock) {
            sysread($sock, my $raw, 128);
            close $sock;
            if ($raw && length($raw) > 5) {
                # MySQL handshake: after 5-byte header, null-terminated version string
                my $ver = '';
                if ($raw =~ /\x0a([\d.]+\-?[^\x00]*)\x00/s) {
                    $ver = $1;
                } elsif (substr($raw, 5) =~ /^([\d.][^\x00]+)/) {
                    $ver = $1;
                }
                log_print("MySQL     (3306): $ver\n\n", 'c') if $ver;
            }
        }
    }

    # PostgreSQL: send startup and read error/auth
    {
        my $sock = IO::Socket::INET->new(
            PeerAddr => $target, PeerPort => 5432,
            Proto => 'tcp', Timeout => $opt{T});
        if ($sock) {
            # Startup message: length(8) + protocol(3.0) + user\0hackbot\0\0
            my $msg = pack('N', 8) . pack('N', 196608);
            print $sock $msg;
            sysread($sock, my $raw, 256);
            close $sock;
            if ($raw && $raw =~ /PostgreSQL|FATAL/) {
                my ($ver) = $raw =~ /PostgreSQL ([\d.]+)/i;
                my $info = $ver ? "PostgreSQL $ver" : "PostgreSQL (auth required)";
                log_print("PostgreSQL(5432): $info\n\n", 'c');
            }
        }
    }

    # Elasticsearch: HTTP GET /
    {
        my $sock = IO::Socket::INET->new(
            PeerAddr => $target, PeerPort => 9200,
            Proto => 'tcp', Timeout => $opt{T});
        if ($sock) {
            print $sock "GET / HTTP/1.0\r\nHost: $target\r\n\r\n";
            sleep(1);
            sysread($sock, my $resp, 2048);
            close $sock;
            if ($resp && $resp =~ /elasticsearch/i) {
                my ($ver) = $resp =~ /"number"\s*:\s*"([^"]+)"/;
                my ($name) = $resp =~ /"cluster_name"\s*:\s*"([^"]+)"/;
                log_print("Elasticsearch(9200): v" . ($ver//'?') .
                          ($name ? " cluster=$name" : '') . "\n\n", 'c');
            }
        }
    }

    # MongoDB: initial handshake reveals version in error message or isMaster
    {
        my $sock = IO::Socket::INET->new(
            PeerAddr => $target, PeerPort => 27017,
            Proto => 'tcp', Timeout => $opt{T});
        if ($sock) {
            # Minimal isMaster OP_QUERY
            my $body = "\x01\x00\x00\x00" .    # flags
                       "admin.\$cmd\x00" .      # collection
                       "\x00\x00\x00\x00" .    # skip
                       "\x01\x00\x00\x00" .    # return 1
                       "\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00";
            my $header = pack('V4', 16 + length($body), 1, 0, 2004);
            print $sock $header . $body;
            sysread($sock, my $raw, 512);
            close $sock;
            if ($raw && $raw =~ /ismaster|MongoDB/i) {
                my ($ver) = $raw =~ /(\d+\.\d+\.\d+)/;
                log_print("MongoDB  (27017): " . ($ver ? "v$ver" : "open, no auth?") . "\n\n", 'c');
            }
        }
    }

    log_print("Service banner scan complete\n\n", 'i');
}

sub _banner_first_line {
    my ($b) = @_;
    $b =~ s/[\r\n].*//s;
    $b =~ s/[^\x20-\x7e]//g;
    return substr($b, 0, 100);
}

# --------------------------------------------------------------------------
# DNSBL / Spam check (extended from original)
# --------------------------------------------------------------------------
sub spamcheck {
    return unless check_ip($target);

    log_print("DNSBL Spam Check\n", 'h');
    log_print("----------------\n", 'h');

    if (is_private_ip($target)) {
        log_print("Private address, skipping DNSBL check\n\n", 'i');
        return;
    }

    my ($a, $b, $c, $d) = split(/\./, $target);
    my $rev = "$d.$c.$b.$a";

    my @lists = (
        ['bl.spamcop.net',           'SpamCop'],
        ['zen.spamhaus.org',         'Spamhaus ZEN'],
        ['b.barracudacentral.org',   'Barracuda'],
        ['dnsbl.sorbs.net',          'SORBS'],
        ['bl.blocklist.de',          'Blocklist.de'],
    );

    for my $list (@lists) {
        my ($bl, $name) = @$list;
        my $listed = gethost("$rev.$bl");
        if ($listed) {
            log_print("LISTED on $name\n", 'c');
        } else {
            log_print("Clean on $name\n", 'i');
        }
    }
    log_print("\n", 'c');
}

# --------------------------------------------------------------------------
# Telnet fingerprint
# --------------------------------------------------------------------------
sub telnetfprint {
    log_print("Telnet fingerprint\n", 'h');
    log_print("------------------\n", 'h');

    unless (-e $fp_db) {
        log_print("Fingerprint database not found ($fp_db), skipping\n\n", 'c');
        return;
    }

    my $sock = IO::Socket::INET->new(
        PeerAddr => $target, PeerPort => 23,
        Proto => 'tcp', Timeout => $opt{T},
    );

    if (!$sock) {
        log_print("No telnet\n\n", 'i');
        return;
    }

    my $fingerprint = '';
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm($opt{T} + 3);
        sysread($sock, my $buff, 14);
        alarm(0);
        if ($buff) {
            $fingerprint .= ord($_) for split(//, $buff);
        }
    };
    close $sock;

    return unless $fingerprint;
    log_print("Fingerprint: $fingerprint\n", 'c');

    open(my $fh, '<', $fp_db) or return;
    my $hit;
    while (<$fh>) {
        chomp;
        my ($desc, $fp, $submitter) = split(/!/, $_, 3);
        if ($fp && $fingerprint eq $fp) {
            log_print("OS guess: $desc (submitted by $submitter)\n\n", 'c');
            $hit = 1;
        }
    }
    close $fh;
    log_print("Fingerprint not in database\n\n", 'c') unless $hit;
}

# --------------------------------------------------------------------------
# Identd scan
# --------------------------------------------------------------------------
sub ident_scan {
    log_print("Identd\n", 'h');
    log_print("------\n", 'h');

    my $sock = IO::Socket::INET->new(
        PeerAddr => $target, PeerPort => 113,
        Proto => 'tcp', Timeout => $opt{T},
    );

    if (!$sock) {
        log_print("No Identd on $target, skipping full scan\n\n", 'i');
        return;
    }

    my ($lp) = unpack_sockaddr_in(getsockname($sock));
    print $sock "113,$lp\r\n";
    sysread($sock, my $buff, 256);
    my (undef, undef, undef, $owner) = split(/:/, $buff // '');
    log_print("Port\tState\tService\tOwner\n", 'h');
    log_print("----\t-----\t-------\t-----\n", 'h');
    log_print("113\tOpen\tident\t$owner", 'c') if $owner;
    close $sock;

    full_identd_scan();
}

sub full_identd_scan {
    my %ports = (21 => 'ftp', 23 => 'telnet', 25 => 'smtp', 80 => 'http', 110 => 'pop3');

    for my $p (sort { $a <=> $b } keys %ports) {
        my $sock = IO::Socket::INET->new(
            PeerAddr => $target, PeerPort => $p,
            Proto => 'tcp', Timeout => $opt{T},
        );
        unless ($sock) {
            log_print("$p\tClosed\t$ports{$p}\t---\n", 'i');
            next;
        }

        my $sock2 = IO::Socket::INET->new(
            PeerAddr => $target, PeerPort => 113,
            Proto => 'tcp', Timeout => $opt{T},
        );
        unless ($sock2) { close $sock; next; }

        my ($lp) = unpack_sockaddr_in(getsockname($sock));
        print $sock2 "$p,$lp\r\n";
        sysread($sock2, my $buff, 256);

        if ($buff && $buff =~ /ERROR/) {
            log_print("$p\tError\t$ports{$p}\tError\n", 'c');
        } elsif ($buff) {
            my (undef, undef, undef, $owner) = split(/:/, $buff);
            log_print("$p\tOpen\t$ports{$p}\t$owner", 'c');
        }
        close $sock; close $sock2;
    }
    log_print("\n", 'c');
}

# --------------------------------------------------------------------------
# Whois lookup
# --------------------------------------------------------------------------
sub whois_lookup {
    log_print("Whois lookup\n", 'h');
    log_print("------------\n", 'h');

    return if is_private_ip($target);

    # Ask IANA which registry handles this IP, then query that registry.
    # Falls back to trying RIPE → ARIN → APNIC in sequence.
    my $iana = _whois_query('whois.iana.org', $target, 4096);
    if ($iana =~ /refer:\s*(whois\.\S+)/i) {
        my $refer = $1;
        if    ($refer =~ /ripe/)  { ripe_whois();  }
        elsif ($refer =~ /arin/)  { arin_whois();  }
        elsif ($refer =~ /apnic/) { apnic_whois(); }
        elsif ($refer =~ /lacnic/) {
            log_print("LACNIC registrar ($refer)\n", 'c');
            my $buff = _whois_query($refer, $target);
            _print_whois_fields($buff,
                'Range'   => 'inetnum',
                'Owner'   => 'owner',
                'Country' => 'country',
            );
        } else {
            # Query the referred server directly
            log_print("Querying $refer\n", 'h');
            my $buff = _whois_query($refer, $target);
            log_print("$buff\n", 'd') if $buff;
        }
    } else {
        # No IANA referral — try registries in order until one returns data
        for my $sub (\&ripe_whois, \&arin_whois, \&apnic_whois) {
            $sub->();
            return;
        }
    }
}

sub _whois_query {
    my ($server, $query, $bufsize) = @_;
    $bufsize //= 16384;

    my $sock = IO::Socket::INET->new(
        PeerAddr => $server, PeerPort => 43,
        Proto => 'tcp', Timeout => $opt{T},
    );
    return '' unless $sock;

    print $sock "$query\n";
    sleep(3);
    sysread($sock, my $buff, $bufsize);
    close $sock;
    return $buff // '';
}

sub _print_whois_fields {
    my ($buff, %fields) = @_;
    while (my ($label, $pattern) = each %fields) {
        if ($buff =~ /$pattern:\s*(.+)/i) {
            my $val = $1; $val =~ s/\s+$//;
            log_print("$label:\t$val\n", 'c');
        }
    }
}

sub ripe_whois {
    log_print("Whois \@RIPE\n", 'h');
    log_print("-----------\n", 'h');
    my $buff = _whois_query('whois.ripe.net', $target);
    _print_whois_fields($buff,
        'Range'   => 'inetnum',
        'Netname' => 'netname',
        'Descr'   => 'descr',
        'Country' => 'country',
        'Email'   => 'e-mail',
    );
    log_print("\n", 'c');
}

sub arin_whois {
    log_print("Whois \@ARIN\n", 'h');
    log_print("-----------\n", 'h');
    my $buff = _whois_query('whois.arin.net', $target, 5120);
    _print_whois_fields($buff,
        'NetRange'   => 'NetRange',
        'Netname'    => 'NetName',
        'Comment'    => 'Comment',
        'TechHandle' => 'TechHandle',
        'TechEmail'  => 'TechEmail',
    );
    log_print("\n", 'c');
}

sub apnic_whois {
    log_print("Whois \@APNIC\n", 'h');
    log_print("------------\n", 'h');
    my $buff = _whois_query('whois.apnic.net', $target);
    _print_whois_fields($buff,
        'Range'   => 'inetnum',
        'Netname' => 'netname',
        'Descr'   => 'descr',
        'Country' => 'country',
        'Email'   => 'e-mail',
    );
    log_print("\n", 'c');
}

# --------------------------------------------------------------------------
# X11 check  (Bug fix v3: alarm() prevents hang)
# --------------------------------------------------------------------------
sub xcheck {
    log_print("X11 access check (port 6000)\n", 'h');
    log_print("----------------------------\n", 'h');

    my $sock = IO::Socket::INET->new(
        PeerAddr => $target, PeerPort => 6000,
        Proto => 'tcp', Timeout => $opt{T},
    );

    if (!$sock) {
        log_print("No X11\n\n", 'i');
        return;
    }

    # FIX: wrap sysread in alarm to prevent indefinite hang (known bug in v2)
    print $sock "\x6c\x00\x0b\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    my $buff = '';
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm($opt{T} + 3);
        sysread($sock, $buff, 4096);
        alarm(0);
    };
    close $sock;

    if ($buff && $buff !~ /protocol|autho/i) {
        log_print("X11 access ALLOWED - no authentication required!\n\n", 'c');
    } else {
        log_print("X11 access not allowed\n\n", 'i');
    }
}

# --------------------------------------------------------------------------
# Proxy test
# --------------------------------------------------------------------------
sub proxytest {
    my ($px, $tgt) = @_;

    my $sock = IO::Socket::INET->new(
        PeerAddr => $px, PeerPort => $proxyport,
        Proto => 'tcp', Timeout => $opt{T} * 2,
    );
    unless ($sock) {
        log_print("Proxy connect failed, scanning without proxy\n\n", 'c');
        undef $proxy; undef $proxyport;
        return;
    }

    log_print("Proxy responds, testing...\n\n", 'c');
    print $sock "GET http://$tgt/_probe_ HTTP/1.0\r\n\r\n";
    sleep(3);
    sysread($sock, my $buff, 1024);
    close $sock;

    if ($buff && $buff =~ /404/) {
        log_print("Proxying allowed\n\n", 'c');
    } else {
        log_print("Proxying not allowed, continuing without proxy\n\n", 'c');
        undef $proxy; undef $proxyport;
    }
}

# --------------------------------------------------------------------------
# IP range handling
# --------------------------------------------------------------------------
sub get_range {
    $start = $ARGV[0];
    $end   = $ARGV[1];

    # Wildcard notation: 192.168.1.*
    if ($start =~ /\*/) {
        my @parts = split(/\./, $start);
        $start = join('.', map { $_ eq '*' ? 0   : $_ } @parts);
        $end   = join('.', map { $_ eq '*' ? 255 : $_ } @parts);
    }

    # CIDR notation
    if ($start =~ m|^([0-9.]+)/(\d+)$|) {
        my ($net, $bits) = ($1, $2);
        die "CIDR masks smaller than /24 are not supported\n" if $bits < 24;
        die "Invalid CIDR mask /$bits\n" if $bits >= 31;
        my ($a, $b, $c, $d) = split(/\./, $net);
        my $nhosts  = 2 ** (32 - $bits);
        my $netmask = 256 - $nhosts;
        $start = $net;
        $end   = "$a.$b.$c." . ($nhosts + $d - 1);
    }

    $end //= $start;
    die "Invalid starting IP\n"  unless check_ip($start);
    die "Invalid ending IP\n"    unless check_ip($end);

    my $s = ip_to_long($start);
    my $e = ip_to_long($end);
    die "Cannot scan backwards\n" if $e < $s;

    for my $n ($s .. $e) {
        push @targetlist, long_to_ip($n);
    }
}

sub ip_to_long {
    my @o = split(/\./, $_[0]);
    return $o[0]*16777216 + $o[1]*65536 + $o[2]*256 + $o[3];
}

sub long_to_ip {
    my $n = $_[0];
    return join('.', int($n/16777216), int($n%16777216/65536),
                     int($n%65536/256), $n%256);
}

# --------------------------------------------------------------------------
# Logging / output
# --------------------------------------------------------------------------
my $log_header = '';

sub header_reset { $log_header = '' }

sub log_print {
    my ($msg, $level) = @_;
    if    ($level eq 'h') { $log_header .= $msg }
    elsif ($level eq 'c') { _emit($log_header); $log_header = ''; _emit($msg) }
    elsif ($level eq 'i') { if ($opt{l} =~ /[vd]/) { _emit($log_header); $log_header = ''; _emit($msg) } }
    elsif ($level eq 'd') { if ($opt{l} =~ /d/)    { _emit($log_header); $log_header = ''; _emit($msg) } }
    else                  { _emit($msg) }
}

sub _emit {
    my ($msg) = @_;
    return unless defined $msg && $msg ne '';

    (my $safe_host = $host // 'unknown') =~ s{[/\\:*?"<>|]}{_}g;
    my $out_path = $opt{O} // "output.$safe_host";
    open(my $fh, '>>', $out_path) or return;
    print $fh $msg;
    close $fh;

    print $msg unless $noprint;
}

# --------------------------------------------------------------------------
# JSON output
# --------------------------------------------------------------------------
sub output_json {
    my $out = $opt{O} ? $opt{O} . '.json' : "output.$host.json";
    $json_results{host}   = $host;
    $json_results{target} = $target;
    $json_results{scanned_at} = strftime("%Y-%m-%dT%H:%M:%S", localtime);

    open(my $fh, '>', $out) or warn "Cannot write JSON to $out: $!\n";
    print $fh JSON::PP->new->pretty->encode(\%json_results);
    close $fh;
    print "JSON results written to $out\n";
}

# --------------------------------------------------------------------------
# Usage
# --------------------------------------------------------------------------
sub usage {
    print <<"END";
HackBot v$VERSION - Network Security Scanner
Usage: hackbot2 [options] <host|ip|range>
       hackbot2 [options] -F <targetfile>

Scan options:
  -A              All scans
  -i              Identd scan
  -t              Telnet fingerprint
  -f              FTP scan
  -m              SMTP/MTA scan (relay, VRFY, EXPN)
  -s              SSH banner
  -S              DNSBL spam check
  -d              DNS version (BIND)
  -r              Whois lookup
  -X              X11 access check
  -H              HTTPS/TLS scan (requires IO::Socket::SSL)
  -g              Geolocation lookup (ip-api.com)
  -p              Port scan (common ports)
  -n              OS detection (HTTP headers + SSH/FTP banners + Nmap if installed)
  -e              Email security: SPF / DKIM / DMARC / MTA-STS
  -B              Service banner scan (IMAP, POP3, Redis, MySQL, Elasticsearch, MongoDB)
  -b              Subdomain scan (crt.sh CT logs + DNS brute-force + AXFR attempt)
  -w <type>       Web scan: a=all v=version o=options c=cgi s=security+cookies+cors d=disclosure
                  (a also runs: redirect chain, CMS, tech stack, error page, mixed content)

Output options:
  -O <file>       Write output to file (default: output.<host>)
  -j, --json      Also write JSON report
  -l <level>      Log level: c=critical (default) v=verbose d=debug
  --color/--no-color  Force color on/off

Network options:
  -a <port>       Alternative webserver port (default: 80)
  -z <secs>       Delay between CGI requests
  -P <host:port>  Use HTTP proxy
  -T <secs>       Connection timeout (default: 5)
  -F <file>       Read targets from file (one per line)

General:
  -V, --version   Print version and exit
  -h, --help      Print this help

Examples:
  hackbot2 -A 192.168.1.1
  hackbot2 -s -m -w a example.com
  hackbot2 -A 192.168.1.0/24
  hackbot2 -p -g -H -j scanme.nmap.org

END
    exit 0;
}
