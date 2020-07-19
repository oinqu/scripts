#!/bin/python3
# -*- coding: utf-8 -*-
"""
Script for checking RBLs asynchronously.

Requires aiodnsresolver (pip install aiodnsresolver).

Usage:
    First argument should be an option from Options enum.
    Second argument should be a single or multiple comma separated IPs.

    python3 rbl_checker.py discovery "8.8.8.8, 4.4.8.8" - For getting LLD items
    python3 rbl_checker.py status "8.8.8.8, 4.4.8.8" - For getting status json from each RBL org.

SEMAPHORE_LIMIT - limits how many dns requests are made simultaneously.
RBL_ORGS - a list of blacklists, largely copied from mxtoolbox.com (19.06.2020)
"""
from aiodnsresolver import Resolver, TYPES, DnsRecordDoesNotExist
from enum import Enum
import ipaddress
import logging
import asyncio
import json
import sys

# The 'aiodnsresolver' logger logs to stdout by default, which is not ideal for zabbix implications.
# If you want to lookup logs then use something like this:
# logging.basicConfig(filename='/log/python/rbl.log', format='%(asctime)s %(levelname)s:%(message)s')
# logging.getLogger("aiodnsresolver").setLevel(logging.DEBUG)
#
# 'aiodnsresolver' logger is disabled to prevent stdout logs.
logging.getLogger("aiodnsresolver").disabled = True

# PS: Sometimes this script spits a couple 'Nameserver failed...' warning level error logs during status check.
# The 'Nameserver failed...' error means that we hit timeout while querying dns server (either /etc/resolv.conf
# or 127.0.0.53). The timeout is set to 0.5s in aiodnsresolver library and, although the entire get_nameservers()
# function can be overwritten, it is (yet) not possible to gracefully overwrite the default timeout value.
# https://github.com/michalc/aiodnsresolver/#custom-nameservers-and-timeouts
#
# For us, the dns timeout most likely means that there is no such A record, therefore we consider the domain
# as a not-listed domain in a particular RBL, so we give it an OK status.

SEMAPHORE_LIMIT = 10
USER_INPUT = sys.argv[1:]
RBL_ORGS = [
    'ips.backscatterer.org',
    'b.barracudacentral.org',
    'bogons.cymru.com',
    'tor.dan.me.uk',
    'torexit.dan.me.uk',
    'dnsbl.dronebl.org',
    'spamrbl.imp.ch',
    'wormrbl.imp.ch',
    'rbl.interserver.net',
    'psbl.surriel.com',
    'spam.spamrats.com',
    'dyna.spamrats.com',
    'noptr.spamrats.com',
    'http.dnsbl.sorbs.net',
    'misc.dnsbl.sorbs.net',
    'smtp.dnsbl.sorbs.net',
    'socks.dnsbl.sorbs.net',
    'spam.dnsbl.sorbs.net',
    'web.dnsbl.sorbs.net',
    'zombie.dnsbl.sorbs.net',
    'block.dnsbl.sorbs.net',
    'dul.dnsbl.sorbs.net',
    'new.spam.dnsbl.sorbs.net',
    'bl.spamcop.net',
    'zen.spamhaus.org',
    'truncate.gbudb.net',
    'dnsbl-1.uceprotect.net',
    'dnsbl-2.uceprotect.net',
    'dnsbl-3.uceprotect.net',
    'db.wpbl.info',
    'bl.0spam.org',
    'rbl.abuse.ro',
    'spam.dnsbl.anonmails.de',
    'bl.blocklist.de',
    'cbl.abuseat.org',
    'cbl.anti-spam.org.cn',
    'rbl.dns-servicios.com',
    'bl.drmx.org',
    'spamsources.fabel.dk',
    'hil.habeas.com',
    'hostkarma.junkemailfilter.com',
    'forbidden.icm.edu.pl',
    'mail-abuse.blacklist.jippg.org',
    'dnsbl.kempt.net',
    'bl.konstant.no',
    'ubl.unsubscore.com',
    'spamguard.leadmon.net',
    'dnsbl.madavi.de',
    'bl.mailspike.net',
    'combined.rbl.msrbl.net',
    'relays.nether.net',
    'unsure.nether.net',
    'ix.dnsbl.manitu.net',
    'bl.nordspam.com',
    'orvedb.aupads.org',
    'all.rbl.jp',
    'rsbl.aupads.org',
    'rbl.schulte.org',
    'backscatter.spameatingmonkey.net',
    'bl.spameatingmonkey.net',
    'bl.score.senderscore.com',
    'korea.services.net',
    'bl.suomispam.net',
    'dnsrbl.imp.ch',
    'uribl.swinog.ch',
    'blacklist.woody.ch',
    'rbl2.triumf.ca',
    'dnsbl.zapbl.net',
    'bl.nosolicitado.org',
]


class Options(Enum):
    discovery = "discovery"
    status = "status"


class Status(Enum):
    ok = "0"
    listed = "1"


class Macros(Enum):
    org = "{#ORG}"
    ip = "{#IPADDR}"


class RblCheck:
    def __init__(self):
        self.options = [op.value for op in Options]
        self.type_of_request = str()
        self.ip_list = list()
        self.output_json = dict()

    def validate_input(self):
        # If there is no options passed to the script
        if not USER_INPUT:
            print("no arguments found")
            sys.exit(1)

        # If some input value is empty (for example empty macro)
        for i in USER_INPUT:
            if i == "":
                print("no option or IP addresses found (check {$APP.RBL.CHECK.IPS} macro)")
                sys.exit(1)

        self.type_of_request = USER_INPUT[0].lower()

        # Validate request type
        if self.type_of_request not in self.options:
            print(f"unknown option: {self.type_of_request}")
            sys.exit(1)

        # Validate input options count
        if len(USER_INPUT) > 2:
            print("too many options passed")
            sys.exit(1)

        if len(USER_INPUT) < 2:
            print("not enough options passed")
            sys.exit(1)

        self.ip_list = [x.strip() for x in USER_INPUT[1].split(',')]

        # Validate IP addresses
        for ip in self.ip_list:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                print(f"ip address is not valid: {ip}")
                sys.exit(1)

    def get_result(self) -> json:
        if self.type_of_request == Options.discovery.value:
            return self.get_discovery()
        if self.type_of_request == Options.status.value:
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(self.get_status())

    def get_discovery(self) -> json:
        output_json = []
        for org in RBL_ORGS:
            for ip in self.ip_list:
                output_json.append({Macros.org.value: org, Macros.ip.value: ip})
        return json.dumps(output_json)

    async def get_status(self) -> json:
        resolver, _ = Resolver()
        sema = asyncio.Semaphore(SEMAPHORE_LIMIT)

        # Initialize output_json dict
        for ip in self.ip_list:
            self.output_json[ip] = list()

        # Create tasks
        tasks = []
        for org in RBL_ORGS:
            for ip in self.ip_list:
                ip_reversed = '.'.join(ip.split('.')[::-1])
                dns = ip_reversed + '.' + org
                tasks.append(self.bound_fetch(sema=sema, resolver=resolver, dns=dns, ip=ip, org=org))

        # Execute tasks and wait until all of them are finished
        await asyncio.gather(*tasks, return_exceptions=False)
        return json.dumps(self.output_json)

    async def bound_fetch(self, sema: asyncio.Semaphore, resolver: Resolver, dns: str, ip: str, org: str):
        async with sema:
            await self.query(resolver=resolver, dns=dns, ip=ip, org=org)

    async def query(self, resolver: Resolver, dns: str, ip: str, org: str):
        try:
            await resolver(dns, TYPES.A)
            self.output_json[ip].append({org: Status.listed.value})
        except DnsRecordDoesNotExist:
            self.output_json[ip].append({org: Status.ok.value})
        except Exception as e:
            print(f"Unknown exception occurred while testing {dns}: {e}")
            self.output_json[ip].append({org: Status.ok.value})


if __name__ == '__main__':
    rbl_check = RblCheck()
    rbl_check.validate_input()
    print(rbl_check.get_result())
