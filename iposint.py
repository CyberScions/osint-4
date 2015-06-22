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
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        parameters = {'ip': badip, 'apikey': '<-- INSERT VIRUSTOTAL API HERE -->'}
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
                    print rd['resolutions'][resolution]['last_resolved'],
                    print '--',
                    print rd['resolutions'][resolution]['hostname']
                print '\n'
            if 'detected_urls' in rd:
                print '[*] DETECTED URLS\n'
                for detected in range(0, len(rd['detected_urls'])):
                    print rd['detected_urls'][detected]['scan_date'],
                    print '--',
                    print rd['detected_urls'][detected]['url']
                print '\n'

            if 'detected_downloaded_samples' in rd:
                print '[*] DETECTED DOWNLOADED SAMPLES\n'
                for detected in range(0, len(rd['detected_downloaded_samples'])):
                    print rd['detected_downloaded_samples'][detected]['date'],
                    print '--',
                    print rd['detected_downloaded_samples'][detected]['positives'],
                    print '--',
                    print rd['detected_downloaded_samples'][detected]['sha256']
                print '\n\n'

            if 'detected_communicating_samples' in rd:
                print '[*] DETECTED COMMUNICATING SAMPLES\n'
                for detected in range(0, len(rd['detected_communicating_samples'])):
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
        
        
def shodanapi(badip):
    try:
        apikey = '<-- INSERT SHODAN API HERE'
        api = shodan.Shodan(apikey)
        request = api.host(badip, history=True)
        print '[*] SHODAN INFO [*]'
        for result in request['data']:
            if 'domains' in result or 'hostnames' in result or 'devicetype' in result:
                if str(result['domains']) != '[]' and str(result['hostnames']) != '[]':
                    print '\n[*] TIMESTAMP\n{0}'.format(result['timestamp'])
                    if 'domains' in result and str(result['domains']) != '[]':
                        print '[*] DOMAINS\n{0}'.format(str(result['domains'])).replace('[u\'', '').replace('\']', '')
                    if 'hostnames' in result and str(result['hostnames']) != '[]':
                        print '[*] HOSTNAMES\n{0}'.format(str(result['hostnames'])).replace('[u\'', '')\
                            .replace('\']', '')
                    if 'devicetype' in result and str(result['devicetype']) != '[]':
                        print '[*] DEVICTYPE\n{0}'.format(result['devicetype'])
                    if 'os' in result and result['os'] is not None:
                        print '[*] OS\n{0}'.format(result['os'])
            else:
                print 'No SHODAN Info'
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
            
        valid_ip(badip)
        ipblocklist(badip)
        virustotal(badip)
        shodanapi(badip)
        targetinfo(badip)
        print 'Total Run Time: {0}'.format(time.time() - starttime)
    except KeyboardInterrupt:
        print '\n[!] Ctrl-C. Exiting.'
        sys.exit()


if __name__ == '__main__':
    main()
