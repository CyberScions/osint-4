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
    resultlist = {
    'resolutions': [],
    'detected_urls': [],
    'detected_downloaded_samples': [],
    'detected_communicating_samples': [],
    'info_url': ''
    }
    try:
        ninetydays = (datetime.datetime.now() - datetime.timedelta(days=90)).strftime('%Y-%m-%d')
        api = open('apikey.txt', 'r').readlines()[0].split()[1]
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        parameters = {'ip': badip, 'apikey': api}
        rd = requests.get(url, params=parameters).json()
        if 'detected_urls' not in rd and 'detected_downloaded_samples' not in rd and 'detected_communicating_samples' \
                not in rd and 'resolutions' not in rd:
            print '\n[*] NO VIRUSTOTAL RESULTS for {0} [*]\n'.format(badip)
        else:
            result_dict = {}
            print '\n[*] VIRUSTOTAL RESULTS [*]'
            if 'resolutions' in rd:
                for resolution in range(0, len(rd['resolutions'])):
                    if rd['resolutions'][resolution]['last_resolved'] >= ninetydays:
                        result_dict['last_resolved'] = rd['resolutions'][resolution]['last_resolved']
                        result_dict['hostname'] = rd['resolutions'][resolution]['hostname']
                        resultlist['resolutions'].append(result_dict)
                        result_dict = {}
            if 'detected_urls' in rd:
                for detected in range(0, len(rd['detected_urls'])):
                    if rd['detected_urls'][detected]['scan_date'] >= ninetydays:
                        result_dict['scan_date'] = rd['detected_urls'][detected]['scan_date']
                        result_dict['url'] = rd['detected_urls'][detected]['url']
                        resultlist['detected_urls'].append(result_dict)
                        result_dict = {}
            if 'detected_downloaded_samples' in rd:
                for detected in range(0, len(rd['detected_downloaded_samples'])):
                    if rd['detected_downloaded_samples'][detected]['date'] >= ninetydays:
                        result_dict['date'] = rd['detected_downloaded_samples'][detected]['date']
                        result_dict['positives'] = rd['detected_downloaded_samples'][detected]['positives']
                        result_dict['sha256'] = rd['detected_downloaded_samples'][detected]['sha256']
                        resultlist['detected_downloaded_samples'].append(result_dict)
                        result_dict = {}
            if 'detected_communicating_samples' in rd:
                for detected in range(0, len(rd['detected_communicating_samples'])):
                    if rd['detected_communicating_samples'][detected]['date'] >= ninetydays:
                        result_dict['date'] = rd['detected_communicating_samples'][detected]['date']
                        result_dict['positives'] = rd['detected_communicating_samples'][detected]['positives']
                        result_dict['sha256'] = rd['detected_communicating_samples'][detected]['sha256']
                        resultlist['detected_communicating_samples'].append(result_dict)
                        result_dict = {}
            resultlist['info_url'] = 'https://www.virustotal.com/en/ip-address{0}/information'.format(badip)
    except Exception, e:
        print e
        return False

    if len(resultlist['resolutions']) > 0:
        print '\n[*] PASSIVETOTAL DNS RESOLUTIONS'
        print 'DATE\t\t\tHOSTNAME'
        print '----\t\t\t--------'
        for item in resultlist['resolutions']:
            print '{0}\t{1}'.format(item['last_resolved'], item['hostname'])
    if len(resultlist['detected_urls']) > 0:
        print '\n[*] DETECTED URLS'
        print 'DATE\t\t\tURL'
        print '----\t\t\t---'
        for item in resultlist['detected_urls']:
            print '{0}\t{1}'.format(item['scan_date'], item['url'])
    if len(resultlist['detected_downloaded_samples']) > 0:
        print '\n[*] DETECTED DOWNLOADED SAMPLES'
        print 'DATE\t\t\tPOS\tSHA256'
        print '----\t\t\t---\t------'
        for item in resultlist['detected_downloaded_samples']:
            print '{0}\t{1}\t{2}'.format(item['date'], item['positives'], item['sha256'])
    if len(resultlist['detected_communicating_samples']) > 0:
        print '\n[*] DETECTED COMMUNICATING SAMPLES'
        print 'DATE\t\t\tPOS\tSHA256'
        print '----\t\t\t---\t------'
        for item in resultlist['detected_communicating_samples']:
            print '{0}\t{1}\t{2}'.format(item['date'], item['positives'], item['sha256'])
    print '\nFOR MORE INFORMATION, PLEASE VISIT THE FOLLOWING URL:\n{0}'.format(resultlist['info_url'])
        
        
def passivetotal(badip):
    resultlist = {
    'unique_resolutions': [],
    'records': []
    }
    try:
        ninetydays = (datetime.datetime.now() - datetime.timedelta(days=90)).strftime('%Y-%m-%d')
        api = open('apikey.txt', 'r').readlines()[3].split()[1]
        url = 'https://www.passivetotal.org/api/v1/passive'
        params = {'api_key': api, 'query': badip}
        json_response = requests.get(url, params=params).json()
        if json_response['success'] is True:
            result_dict = {}
            print '[*] PASSIVETOTAL RESULTS [*]\n'
            for result in json_response['results']['unique_resolutions']:
                result_dict['unique_resolutions'] = result
                resultlist['unique_resolutions'].append(result_dict)
                result_dict = {}
            for record in range(0, len(json_response['results']['records'])):
                if json_response['results']['records'][record]['lastSeen'] >= ninetydays:
                    source = str(json_response['results']['records'][record]['source'])
                    source = source.replace('[u', '').replace(']', '').replace('u\'', '').replace('\'', '')
                    result_dict['source'] = source
                    result_dict['resolve'] = json_response['results']['records'][record]['resolve']
                    result_dict['lastSeen'] = json_response['results']['records'][record]['lastSeen']
                    resultlist['records'].append(result_dict)
                    result_dict = {}
        else:
            print '[*] NO PASSIVETOTAL RESULTS [*]\n'
    except Exception, e:
        print '[!] Error! {0}'.format(e)

    if len(resultlist['unique_resolutions']) > 0:
        print '\n[*] UNIQUE RESOLUTIONS'
        for item in resultlist['unique_resolutions']:
            print '{0}'.format(item['unique_resolutions'])
    if len(resultlist['records']) > 0:
        print '\n[*] RECORDS'
        print 'DATE\t\t\tSOURCE[s]\t\tURL'
        print '----\t\t\t---------\t\t---'
        for item in resultlist['records']:
            print '{0}\t{1}\t{2}'.format(item['lastSeen'], item['source'], item['resolve'])


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
