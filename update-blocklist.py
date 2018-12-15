#!/usr/bin/env python3

import requests
from pathlib import Path
from datetime import datetime
import email.utils as eut
import os
import hashlib
import re
import sys

import subprocess
import textwrap

#import pprint
#pp = pprint.PrettyPrinter(indent=4)

whitelist = [
	# http://someonewhocares.org/hosts/zero/hosts
	# breaks hotmail.com logins
	'a-msedge.net',

	# required for newspaper videos
	'cdns.gigya.com',

    # newrelic ansible blog
    'blog.newrelic.com',

    # linkedin.com
    'cedexis.net',
]

config = {
    # Blocklist download request timeout
    'req_timeout_s': 10,
    # Also block *.domain.tld
    'wildcard_block': True
}

regex_domain = '^(127|0)\\.0\\.0\\.(0|1)[\\s\\t]+(?P<domain>([a-z0-9\\-_]+\\.)+[a-z][a-z0-9_-]*)$'
regex_no_comment = '^#.*|^$'

regex_adguard_filters = '^\|\|(?P<domain>([a-z0-9\\-_]+\\.)+[a-z][a-z0-9_-]*)\^'

unit42_domains = '^(?P<domain>([a-z0-9\\-_]+\\.)+[a-z][a-z0-9_-]*)'

lists = [
    {'url': 'http://172.30.5.69/my-blocked-domains.txt', 'regex': regex_domain, 'filter': regex_no_comment},
    {'url': 'https://pgl.yoyo.org/as/serverlist.php?hostformat=nohtml&showintro=0', 'filter': regex_no_comment},
    {'url': 'http://mirror1.malwaredomains.com/files/justdomains', 'filter': regex_no_comment},
    {'url': 'http://winhelp2002.mvps.org/hosts.txt', 'regex': regex_domain, 'filter': regex_no_comment},
    {'url': 'https://adaway.org/hosts.txt', 'regex': regex_domain, 'filter': regex_no_comment},
    {'url': 'https://hosts-file.net/ad_servers.txt', 'regex': regex_domain, 'filter': regex_no_comment},
    {'url': 'http://someonewhocares.org/hosts/zero/hosts', 'regex': regex_domain, 'filter': regex_no_comment},
    {'url': 'https://www.malwaredomainlist.com/hostslist/hosts.txt', 'regex': regex_domain, 'filter': regex_no_comment},

    #
    # adlists from pi-hole: https://github.com/pi-hole/pi-hole/blob/master/adlists.default
    #
    # The below list amalgamates several lists we used previously.
    # See `https://github.com/StevenBlack/hosts` for details
    # StevenBlack's list
    {'url': 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts', 'regex': regex_domain, 'filter': regex_no_comment},
    # Cameleon
    {'url': 'http://sysctl.org/cameleon/hosts', 'regex': regex_domain, 'filter': regex_no_comment},
    # Zeustracker
    {'url': 'https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist', 'filter': regex_no_comment},
    # Disconnect.me Tracking
    {'url': 'https://s3.amazonaws.com/lists.disconnect.me/simple_tracking.txt', 'filter': regex_no_comment},
    # Disconnect.me Ads
    {'url': 'https://s3.amazonaws.com/lists.disconnect.me/simple_ad.txt', 'filter': regex_no_comment},

    #
    # My own add-ons
    #
    {'url': 'https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers.txt', 'regex': regex_adguard_filters, 'filter': regex_no_comment},
    {'url': 'https://github.com/AdguardTeam/AdguardFilters/raw/master/MobileFilter/sections/adservers.txt', 'regex': regex_adguard_filters, 'filter': regex_no_comment},
    {'url': 'https://github.com/AdguardTeam/AdguardFilters/raw/master/EnglishFilter/sections/adservers.txt', 'regex': regex_adguard_filters, 'filter': regex_no_comment},
    {'url': 'https://github.com/AdguardTeam/AdguardDNS/raw/master/Filters/filter.txt', 'regex': regex_adguard_filters, 'filter': regex_no_comment},
    {'url': 'https://raw.githubusercontent.com/easylist/easylist/master/easylist/easylist_adservers.txt', 'regex': regex_adguard_filters, 'filter': regex_no_comment},
    {'url': 'https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers_firstparty.txt', 'regex': regex_adguard_filters, 'filter': regex_no_comment},
    {'url': 'https://raw.githubusercontent.com/AdguardTeam/AdguardFilters/master/SpywareFilter/sections/tracking_servers.txt', 'regex': regex_adguard_filters, 'filter': regex_no_comment},
    # unit42
    {'url': 'https://github.com/pan-unit42/iocs/raw/master/notepadcase/Domain_listing.txt', 'regex': unit42_domains, 'filter': regex_no_comment},
    {'url': 'https://github.com/pan-unit42/iocs/raw/master/coinhive/top_domains.txt', 'regex': unit42_domains, 'filter': regex_no_comment},

    #{'url': '', 'regex': regex_adguard_filters, 'filter': regex_no_comment},

]

def download_list(url):
    headers = None

    cache = Path('.cache', 'bind_adblock')
    if not cache.is_dir():
        cache.mkdir(parents=True)
    cache = Path(cache, hashlib.sha1(url.encode()).hexdigest())

    if cache.is_file():
        last_modified = datetime.utcfromtimestamp(cache.stat().st_mtime)
        headers = {
                'If-modified-since': eut.format_datetime(last_modified),
                'User-Agent': 'Bind adblock zonfile updater v1.0 (https://github.com/Trellmor/bind-adblock)'
                }

    try:
        r = requests.get(url, headers=headers, timeout=config['req_timeout_s'])

        if r.status_code == 200:
            with cache.open('w') as f:
                f.write(r.text)
            
            if 'last-modified' in r.headers:
                last_modified = eut.parsedate_to_datetime(r.headers['last-modified']).timestamp()
                os.utime(str(cache), times=(last_modified, last_modified))

            return r.text
    except requests.exceptions.RequestException as e:
        print(e)

    if cache.is_file():
        with cache.open() as f:
            return f.read()

def parse_lists():
    domains = set()

    for l in lists:
        data = download_list(l['url'])
        if data:
            print(l["url"])

            lines = data.splitlines()
            print("\t{} lines".format(len(lines)))

            c = len(domains)

            for line in data.splitlines():
                domain = ''

                if 'filter' in l:
                    m = re.match(l['filter'], line)
                    if m:
                        continue

                if 'regex' in l:
                    m = re.match(l['regex'], line)
                    if m:
                        domain = m.group('domain')
                else:
                    domain = line

                domain = domain.strip()
                domains.add(domain)

            print("\t{} new domains".format(len(domains) - c))

    print("\nTotal\n\t{} domains".format(len(domains)))
    return domains


def usage(code=0):
    print('Usage: update-blocklist.py blocklist.txt')
    exit(code)

if len(sys.argv) != 2:
    usage(1)

zonefile = sys.argv[1]

domains = parse_lists() # is a set()

# remove whitelisted domains
for white in whitelist:
    try:
        domains.remove(white)
        print(white, "removed as whitelisted")
    except Exception as e:
        print(white, "is whitelisted but not found")

with Path(zonefile).open('a') as f:
    for d in (sorted(domains)):
        f.write('0.0.0.0 ' + d + '\n')
 