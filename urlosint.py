#!/usr/bin/env python

__author__ = 'funtime'
__version__ = '0.5'

import re
import os
import sys
import time
import json
import urllib
import urllib2
import threading
from xml.dom.minidom import parseString


def color(text, color_code):
    if sys.platform == "win32" and os.getenv("TERM") != "xterm":
        return text

    return '\x1b[%dm%s\x1b[0m' % (color_code, text)


def red(text):
    return color(text, 31)


def domainblocklist(domain):
    blocklists = {
        'http://hosts-file.net/download/hosts.txt': 'MalwareBytes',
        'http://antispam.imp.ch/swinog-uri-rbl.txt': 'antispam.imp.ch URI RBL',
        'http://antispam.imp.ch/spamlist': 'antispam.imp.ch Spamlist',
        'https://zeustracker.abuse.ch/blocklist.php?download=domainblocklist': 'ZeusTracker',
        'https://palevotracker.abuse.ch/blocklists.php?download=domainblocklist': 'PalevoTracker',
        'https://feodotracker.abuse.ch/blocklist/?download=domainblocklist': 'FeodoTracker',
        'http://mirror1.malwaredomains.com/files/domains.txt': 'MalwareDomains',
        'http://malc0de.com/bl/ZONES': 'malc0de',
        'http://www.malwaredomainlist.com/hostslist/hosts.txt': 'MalwareDomainList',
        'http://osint.bambenekconsulting.com/feeds/c2-dommasterlist.txt': 'Bambenek C2 Domains',
    }

    def threadurl(domain, url, org):
        try:
            request = urllib2.Request(url)
            request.add_header('User-Agent', 'Mozilla/5.0 (X11, Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) '
                                             'Chrome/35.0.1916.153 Safari/537.36')
            html_content = urllib2.build_opener().open(request).read()
            matches = re.findall(domain, html_content)
            if domain in matches:
                print red('{0} is on the {1} list.'.format(domain, org))
            else:
                print '{0} is NOT on the {1} list.'.format(domain, org)
        except Exception, e:
            print '[!] Error! {0}'.format(e)
            return False

    for url, org in blocklists.items():
        t = threading.Thread(target=threadurl, args=(domain, url, org))
        t.start()
        t.join()


def urlvoid(domain):
    url = 'http://api.urlvoid.com/api1000'
    apikey = 'd05ab69cd8267f2dcd8c6ae4de452d0b71f1a7e1'
    url = '{0}/{1}/host/{2}'.format(url, apikey, domain)
    request = urllib2.urlopen('{0}/'.format(url)).read()
    dom = parseString(request)
    try:
        if 'detections' in dom.getElementsByTagName('detections')[0].toxml():
            print '\nURLVOID ENGINE DETECTIONS\n'
            xmldate = dom.getElementsByTagName('updated')[0].toxml()
            xmldate = xmldate.replace('<updated>', '').replace('</updated>', '')
            xmldate = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(float(xmldate)))
            xmltag = dom.getElementsByTagName('detections')[0].toxml()
            xmldetections = xmltag.replace('<detections>', '').replace('</detections', '').replace('<engines>', '') \
                .replace('</engines>', '').replace('<engine>', '').replace('</engine>', '').replace('<count>', '') \
                .replace('</count>', '').replace('>', '').replace(' ', '')
            print '\nLastScanDate\n{0}\n'.format(xmldate)
            print 'Detected Engines\n{0}'.format(xmldetections)
    except Exception:
        print '\nNO URLVOID ENGINE DETECTIONS\n'


def virustotal(domain):
    try:
        url = 'https://www.virustotal.com/vtapi/v2/domain/report'
        parameters = {'domain': domain, 'apikey': '<-- INSERT VIRUSTOTAL API HERE -->'}
        response = urllib.urlopen('{0}?{1}'.format(url, urllib.urlencode(parameters))).read()
        rd = json.loads(response)
        if 'resolutions' not in rd and 'subdomains' not in rd and 'detected_urls' not in rd \
                and 'detected_downloaded_samples' not in rd and 'detected_referrer_samples' not in rd \
                and 'detected_communicating_samples' not in rd:
            print '\nNO VIRUSTOTAL RESULTS for {0}\n'.format(domain)
        else:
            print '\nVIRUSTOTAL RESULTS\n'
            if 'resolutions' in rd:
                print '[*] DETECTED IP ADDRESS RESOLUTIONS\n'
                for resolution in range(0, len(rd['resolutions'])):
                    print rd['resolutions'][resolution]['last_resolved'],
                    print '--',
                    print rd['resolutions'][resolution]['ip_address']
                print '\n'
            if 'subdomains' in rd:
                print '[*] DETECTED SUBDOMAINS\n'
                for subdomain in range(0, len(rd['subdomains'])):
                    print rd['subdomains'][subdomain]
                print '\n'
            if 'detected_urls' in rd:
                print '[*] DETECTED URLS\n'
                for detected in range(0, len(rd['detected_urls'])):
                    print rd['detected_urls'][detected]['scan_date'],
                    print '--',
                    print rd['detected_urls'][detected]['positives'],
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
                print '\n'
            if 'detected_referrer_samples' in rd:
                print '[*] DETECTED REFERRER SAMPLES\n'
                for detected in range(0, len(rd['detected_referrer_samples'])):
                    print rd['detected_referrer_samples'][detected]['positives'],
                    print '--',
                    print rd['detected_referrer_samples'][detected]['sha256']
                print '\n'
            if 'detected_communicating_samples' in rd:
                print '[*] DETECTED COMMUNICATING SAMPLES\n'
                for detected in range(0, len(rd['detected_communicating_samples'])):
                    print rd['detected_communicating_samples'][detected]['date'],
                    print '--',
                    print rd['detected_communicating_samples'][detected]['positives'],
                    print '--',
                    print rd['detected_communicating_samples'][detected]['sha256']
                print '\n\n'

            print 'FOR MORE INFORMATION, FOLLOW THIS LINK\n'
            print 'https://www.virustotal.com/en/domain/{0}/information/'.format(domain)
    except Exception, e:
        print '[!] Error! {0}'.format(e)


def targetinfo(domain):
    try:
        dnslookup = urllib.urlopen('http://api.hackertarget.com/dnslookup/?q={0}'.format(domain)).read()
        httpheaders = urllib.urlopen('http://api.hackertarget.com/httpheaders/?q={0}'.format(domain)).read()

        print 'DNS LOOKUP\n{0}\n\n'.format(dnslookup)
        print 'HTTP HEADERS\n{0}\n\n'.format(httpheaders)
    except Exception, e:
        print '[!] Error! {0}'.format(e)
        return False


def main():
    try:
        if len(sys.argv) != 2:
            domain = raw_input('Enter Domain to Query: ')
        else:
            domain = sys.argv[1]
        starttime = time.time()
        domainblocklist(domain)
        urlvoid(domain)
        virustotal(domain)
        targetinfo(domain)
        print 'Total Run Time: {0}'.format(time.time() - starttime)
    except KeyboardInterrupt:
        print '\n[!] Ctrl-C. Exiting.'


if __name__ == '__main__':
    main()
