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
import requests
import datetime
import threading
from xml.dom.minidom import parseString


def color(text, color_code):
    if sys.platform == "win32" and os.getenv("TERM") != "xterm":
        return text

    return '\x1b[%dm%s\x1b[0m' % (color_code, text)


def red(text):
    return color(text, 31)


def domainblocklist(domain):
    resultlist = {'blocklists': []}
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
        result_dict = []
        try:
            header = {'user-agent': 'Mozilla/5.0 (X11, Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) '
                                             'Chrome/35.0.1916.153 Safari/537.36'}
            request = requests.get(url, header=header)
            if domain in request.content:
                result_dict.append(org)
                resultlist['blocklists'].append(result_dict)
            else:
                pass
        except Exception, e:
            print '[!] Error! {0}'.format(e)
            return False

    for url, org in blocklists.items():
        t = threading.Thread(target=threadurl, args=(domain, url, org))
        t.start()
        t.join()

    if resultlist['blocklists'] > 0:
        print '[*] BLOCKLIST RESULTS [*]'
        for item in resultlist['blocklists']:
            print red(str(item)).replace('[\'', '').replace('\']', '')
    else:
        print '{0} NOT ON ANY BLOCKLISTS'.format(domain)


def urlvoid(domain):
    url = 'http://api.urlvoid.com/api1000'
    apikey = open('apikey.txt', 'r').readlines()[1].split()[1]
    url = '{0}/{1}/host/{2}'.format(url, apikey, domain)
    request = urllib2.urlopen('{0}/'.format(url)).read()
    dom = parseString(request)
    try:
        if 'detections' in dom.getElementsByTagName('detections')[0].toxml():
            print '\n[*] URLVOID ENGINE DETECTIONS [*]'
            xmldate = dom.getElementsByTagName('updated')[0].toxml()
            xmldate = xmldate.replace('<updated>', '').replace('</updated>', '')
            xmldate = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(float(xmldate)))
            xmltag = dom.getElementsByTagName('detections')[0].toxml()
            xmldetections = xmltag.replace('<detections>', '').replace('</detections', '').replace('<engines>', '') \
                .replace('</engines>', '').replace('<engine>', '').replace('</engine>', '').replace('<count>', '') \
                .replace('</count>', '').replace('>', '').replace(' ', '')
            print '\n[*] LastScanDate\n{0}\n'.format(xmldate)
            print '[*] Detected Engines{0}'.format(xmldetections)
    except Exception:
        print '\n[*] NO URLVOID ENGINE DETECTIONS [*]\n'


def virustotal(domain):
    resultlist = {
    'resolutions': [],
    'subdomains': [],
    'detected_urls': [],
    'detected_downloaded_samples': [],
    'detected_referrer_samples': [],
    'detected_communicating_samples': [],
    'info_url': ''
    }
    try:
        ninetydays = (datetime.datetime.now() - datetime.timedelta(days=90)).strftime('%Y-%m-%d')
        api = open('apikey.txt', 'r').readlines()[0].split()[1]
        url = 'https://www.virustotal.com/vtapi/v2/domain/report'
        parameters = {'domain': domain, 'apikey': api}
        rd = requests.get(url, params=parameters).json()
        if 'resolutions' not in rd and 'subdomains' not in rd and 'detected_urls' not in rd \
                and 'detected_downloaded_samples' not in rd and 'detected_referrer_samples' not in rd \
                and 'detected_communicating_samples' not in rd:
            print '\n[*] NO VIRUSTOTAL RESULTS for {0} [*]\n'.format(domain)
        else:
            result_dict = {}
            if 'resolutions' in rd:
                for resolution in range(0, len(rd['resolutions'])):
                    if rd['resolutions'][resolution]['last_resolved'] >= ninetydays:
                        result_dict['last_resolved'] = rd['resolutions'][resolution]['last_resolved']
                        result_dict['ip_address'] = rd['resolution'][resolution]['ip_address']
                        resultlist['resolutions'].append(result_dict)
                        result_dict = {}
            if 'subdomains' in rd:
                for subdomain in range(0, len(rd['subdomains'])):
                    result_dict['subdomain'] = rd['subdomains'][subdomain]
                    resultlist['subdomains'].append(result_dict)
                    result_dict = {}
            if 'detected_urls' in rd:
                for detected in range(0, len(rd['detected_urls'])):
                    if rd['detected_urls'][detected]['scan_date'] >= ninetydays:
                        result_dict['scan_date'] = rd['detected_urls'][detected]['scan_date']
                        result_dict['positives'] = rd['detected_urls'][detected]['positives']
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
            if 'detected_referrer_samples' in rd:
                for detected in range(0, len(rd['detected_referrer_samples'])):
                    result_dict['positives'] = rd['detected_referrer_samples'][detected]['positives']
                    result_dict['sha256'] = rd['detected_referrer_samples'][detected]['sha256']
                    resultlist['detected_referrer_samples'].append(result_dict)
                    result_dict = {}
            if 'detected_communicating_samples' in rd:
                for detected in range(0, len(rd['detected_communicating_samples'])):
                    if rd['detected_communicating_samples'][detected]['date'] >= ninetydays:
                        result_dict['date'] = rd['detected_communicating_samples'][detected]['date']
                        result_dict['positives'] = rd['detected_communicating_samples'][detected]['positives']
                        result_dict['sha256'] = rd['detected_communicating_samples'][detected]['sha256']
                        resultlist['detected_communicating_samples'].append(result_dict)
                        result_dict = {}
            resultlist['info_url'] = 'https://www.virustotal.com/en/domain/{0}/information/\n'.format(domain)
    except Exception, e:
        print '[!] Error! {0}'.format(e)

    if len(resultlist['resolutions']) > 0:
        print '\n[*] PASSIVE DNS RESOLUTIONS'
        print 'DATE\t\t\tIP ADDRESS'
        print '----\t\t\t-- -------'
        for item in resultlist['resolutions']:
            print '{0}\t{1}'.format(item['last_resolved'], item['ip_address'])
    if len(resultlist['subdomains']) > 0:
        print '\n[*] SUBDOMAINS'
        for item in resultlist['subdomains']:
            print '{0}'.format(item['subdomain'])
    if len(resultlist['detected_urls']) > 0:
        print '\n[*] DETECTED URLs'
        print 'DATE\t\t\tPOS\tURL'
        print '----\t\t\t---\t---'
        for item in resultlist['detected_urls']:
            print '{0}\t{1}\t{2}'.format(item['scan_date'], item['positives'], item['url'])
    if len(resultlist['detected_downloaded_samples']) > 0:
        print '\n[*] DETECTED DOWNLOADED SAMPLES'
        print 'DATE\t\t\tPOS\tSHA256'
        print '----\t\t\t---\t------'
        for item in resultlist['detected_downloaded_samples']:
            print '{0}\t{1}\t{2}'.format(item['date'], item['positives'], item['sha256'])
    if len(resultlist['detected_referrer_samples']) > 0:
        print '\n[*] DETECTED REFERRER SAMPLES'
        print 'POS\tSHA256'
        print '---\t------'
        for item in resultlist['detected_referrer_samples']:
            print '{0}\t{1}'.format(item['positives'], item['sha256'])
    if len(resultlist['detected_communicating_samples']) > 0:
        print '\n[*] DETECTED COMMUNICATING SAMPLES'
        print 'DATE\t\t\tPOS\tSHA256'
        print '----\t\t\t---\t------'
        for item in resultlist['detected_communicating_samples']:
            print '{0}\t{1}\t{2}'.format(item['date'], item['positives'], item['sha256'])
    print '\nFOR MORE INFORMATION, PLEASE VISIT THE FOLLOWING URL:\n{0}'.format(resultlist['info_url'])
    
    
def passivetotal(domain):
    resultlist = {
    'unique_resolutions': [],
    'records': []
    }
    try:
        ninetydays = (datetime.datetime.now() - datetime.timedelta(days=90)).strftime('%Y-%m-%d')
        api = open('apikey.txt', 'r').readlines()[3].split()[1]
        url = 'https://www.passivetotal.org/api/v1/passive'
        params = {'api_key': api, 'query': domain}
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
        print 'DATE\t\t\tSOURCE[s]\tIP ADDRESS'
        print '----\t\t\t---------\t----------'
        for item in resultlist['records']:
            print '{0}\t{1}\t\t{2}'.format(item['lastSeen'], item['source'], item['resolve'])


def targetinfo(domain):
    try:
        dnslookup = requests.get('http://api.hackertarget.com/dnslookup/?q={0}'.format(domain))
        httpheaders = requests.get('http://api.hackertarget.com/httpheaders/?q={0}'.format(domain))
        
        print '\n[*] GENERAL DOMAIN INFO [*]\n'
        print '[*] DNS LOOKUP\n{0}\n\n'.format(dnslookup.content)
        print '[*] HTTP HEADERS\n{0}\n\n'.format(httpheaders.content)
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
        passivetotal(domain)
        targetinfo(domain)
        print 'Total Run Time: {0}'.format(time.time() - starttime)
    except KeyboardInterrupt:
        print '\n[!] Ctrl-C. Exiting.'


if __name__ == '__main__':
    main()
