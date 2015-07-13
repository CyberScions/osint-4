#!/usr/bin/env python

__author__ = 'funtime'
__version__ = '1.0'

import re
import os
import sys
import json
import time
import shodan
import urllib
import urllib2
import requests
import datetime
import threading


def color(text, color_code):
    if sys.platform == "win32" and os.getenv("TERM") != "xterm":
        return text

    return '\x1b[%dm%s\x1b[0m' % (color_code, text)
    

def red(text):
    return color(text, 31)


def ipblocklist(badip):
    blocklists = {
        'http://rules.emergingthreats.net/blockrules/compromised-ips.txt': 'EmergingThreats',
        'http://www.blocklist.de/lists/all.txt': 'BlocklistDE',
        'http://www.openbl.org/lists/date_all.txt': 'OpenBL',
        'https://www.openbl.org/lists/base.txt': 'OpenBL Last 90 Days',
        'http://www.nothink.org/blacklist/blacklist_malware_http.txt': 'NoThink Malware',
        'http://www.nothink.org/blacklist/blacklist_ssh_all.txt': 'NoThink SSH',
        'http://antispam.imp.ch/spamlist': 'antispam.imp.ch',
        'http://www.dshield.org/ipsascii.html?limit=10000': 'dshield',
        'http://malc0de.com/bl/IP_Blacklist.txt': 'malc0de',
        'http://hosts-file.net/rss.asp': 'MalwareBytes',
        'https://zeustracker.abuse.ch/blocklist.php?download=badips': 'ZeusTracker',
        'https://palevotracker.abuse.ch/blocklists.php?download=ipblocklist': 'PalevoTracker',
        'https://feodotracker.abuse.ch/blocklist/?download=ipblocklist': 'FeodoTracker',
        'http://www.malwaredomainlist.com/hostslist/ip.txt': 'MalwareDomainList',
        'http://virbl.bit.nl/download/virbl.dnsbl.bit.nl.txt': 'VirBL',
        'http://www.autoshun.org/files/shunlist.html': 'AutoShun',
        'http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt': 'Bambenek C2 IP',
        'http://dragonresearchgroup.org/insight/http-report.txt': 'Dragon Research HTTP',
        'http://dragonresearchgroup.org/insight/sshpwauth.txt': 'Dragon Research SSH',
        'http://cinsscore.com/list/ci-badguys.txt': 'CI Army',
        'http://www.cruzit.com/xwbl2csv.php': 'CruzIT',
        'http://www.binarydefense.com/banlist.txt': 'BinaryDefense'
    }

    def threadurl(url, badip, org):
        try:
            request = urllib2.Request(url)
            request.add_header('User-Agent', 'Mozilla/5.0 (X11, Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) '
                                             'Chrome/35.0.1916.153 Safari/537.36')
            html_content = urllib2.build_opener().open(request).read()
            matches = re.findall(badip, html_content)
            if badip in matches:
                print red('{0} is on the {1} list.'.format(badip, org))
            else:
                print '{0} is NOT on the {1} list.'.format(badip, org)
        except Exception, e:
            print '[!] Error! {0}'.format(e)
            return False
            
    print '\n[*] BLOCKLIST RESULTS [*]\n'

    for url, org in blocklists.items():
        t = threading.Thread(target=threadurl, args=(url, badip, org))
        t.start()
        t.join()


def virustotal(badip):
    try:
        ninetydays = datetime.datetime.now() - datetime.timedelta(days=90)
        ninetydaysformat = ninetydays.strftime('%Y-%m-%d')
        api = open('apikey.txt', 'r').readlines()[0].split()[1]
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        parameters = {'ip': badip, 'apikey': api}
        response = urllib2.urlopen('{0}?{1}'.format(url, urllib.urlencode(parameters), timeout=30)).read()
        response_dict = json.loads(response)
        rd = response_dict
        if 'detected_urls' not in rd and 'detected_downloaded_samples' not in rd and 'detected_communicating_samples' \
                not in rd and 'resolutions' not in rd:
            print '\n[*] NO VIRUSTOTAL RESULTS for {0} [*]\n'.format(badip)
        else:
            print '\n[*] VIRUSTOTAL RESULTS [*]\n'
            if 'resolutions' in rd:
                print '[*] PASSIVE DNS RESOLUTIONS\n'
                for resolution in range(0, len(rd['resolutions'])):
                    if rd['resolutions'][resolution]['last_resolved'] >= ninetydaysformat:
                        print rd['resolutions'][resolution]['last_resolved'],
                        print '--',
                        print rd['resolutions'][resolution]['hostname']
                print '\n'
            if 'detected_urls' in rd:
                print '[*] DETECTED URLS\n'
                for detected in range(0, len(rd['detected_urls'])):
                    if rd['detected_urls'][detected]['scan_date'] >= ninetydaysformat:
                        print rd['detected_urls'][detected]['scan_date'],
                        print '--',
                        print rd['detected_urls'][detected]['url']
                print '\n'

            if 'detected_downloaded_samples' in rd:
                print '[*] DETECTED DOWNLOADED SAMPLES\n'
                for detected in range(0, len(rd['detected_downloaded_samples'])):
                    if rd['detected_downloaded_samples'][detected]['date'] >= ninetydaysformat:
                        print rd['detected_downloaded_samples'][detected]['date'],
                        print '--',
                        print rd['detected_downloaded_samples'][detected]['positives'],
                        print '--',
                        print rd['detected_downloaded_samples'][detected]['sha256']
                print '\n\n'

            if 'detected_communicating_samples' in rd:
                print '[*] DETECTED COMMUNICATING SAMPLES\n'
                for detected in range(0, len(rd['detected_communicating_samples'])):
                    if rd['detected_communicating_samples'][detected]['date'] >= ninetydaysformat:
                        print rd['detected_communicating_samples'][detected]['date'],
                        print '--',
                        print rd['detected_communicating_samples'][detected]['positives'],
                        print '--',
                        print rd['detected_communicating_samples'][detected]['sha256']
                print '\n\n'

            print 'FOR MORE INFORMATION, FOLLOW THIS LINK:'
            print 'https://www.virustotal.com/en/ip-address/{0}/information/\n'.format(badip)
    except Exception, e:
        print '[!] Error! {0}'.format(e)
        return False
        
        
def passivetotal(badip):
    try:
        ninetydays = datetime.datetime.now() - datetime.timedelta(days=90)
        ninetydaysformat = ninetydays.strftime('%Y-%m-%d')
        api = apikey = open('apikey.txt', 'r').readlines()[3].split()[1]
        url = 'https://www.passivetotal.org/api/v1/passive'
        params = {'api_key': api, 'query': badip}
        response = requests.get(url, params=params)
        json_response = json.loads(response.content)
        if json_response['success'] is True:
            print '[*] PASSIVETOTAL RESULTS [*]'
            print '\n[*] UNIQUE RESOLUTIONS'
            for result in json_response['results']['unique_resolutions']:
                print result
            print '\n[*] RECORDS'
            for record in range(0, len(json_response['results']['records'])):
                if json_response['results']['records'][record]['lastSeen'] >= ninetydaysformat:
                    source = str(json_response['results']['records'][record]['source'])
                    print source.replace('[u', '').replace(']', '').replace('u\'', '').replace('\'', ''),
                    print '--',
                    print json_response['results']['records'][record]['resolve'],
                    print '--',
                    print json_response['results']['records'][record]['lastSeen']
        else:
            print '[*] NO PASSIVETOTAL RESULTS [*]'
    except Exception, e:
        print '[!] Error! {0}'.format(e)


def targetinfo(badip):
    try:
        reversedns = urllib2.urlopen('http://api.hackertarget.com/reverseiplookup/?q={0}'.format(badip)).read()
        geoip = urllib2.urlopen('http://api.hackertarget.com/geoip/?q={0}'.format(badip)).read()
        whois = urllib2.urlopen('http://api.hackertarget.com/whois/?q={0}'.format(badip)).read()
        httpheaders = urllib2.urlopen('http://api.hackertarget.com/httpheaders/?q={0}'.format(badip)).read()
        
        print '\n[*] GENERAL IP INFO [*]\n'
        print '[*] REVERSE DNS\n{0}\n'.format(reversedns)
        print '[*] GEOIP\n{0}\n'.format(geoip)
        print '[*] WHOIS\n{0}\n'.format(whois)
        print '[*] HTTP HEADERS\n{0}\n'.format(httpheaders)
    except Exception, e:
        print '[!] Error! {0}'.format(e)
        return False


def valid_ip(badip):
    pattern = r'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]\
    |[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    if re.match(pattern, badip):
        return True
    else:
        print '\n{0} invalid!!\nPlease enter valid IP address'.format(badip)
        sys.exit()


def main():
    try:
        if len(sys.argv) != 2:
            badip = raw_input('Enter IP address: ')
        else:
            badip = sys.argv[1]
            
        starttime = time.time()
            
        #valid_ip(badip)
        ipblocklist(badip)
        virustotal(badip)
        passivetotal(badip)
        targetinfo(badip)
        print 'Total Run Time: {0}'.format(time.time() - starttime)
    except KeyboardInterrupt:
        print '\n[!] Ctrl-C. Exiting.'
        sys.exit()


if __name__ == '__main__':
    main()
