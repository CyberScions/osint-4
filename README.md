# iposint
Query IP address against public blocklists, VirusTotal and PassiveTotal Passive DNS
* Install ShodanAPI in order to use Shodan functions

# urlosint
Query domain against public blocklists, VirusTotal and URLVoid

# usage
Create a file called apikey.txt that contains your VirusTotal, URLVoid and Shodan API Keys.<br>
The file format should be as follows:<br>
virustotal: <-- ENTER APIKEY HERE --><br>
urlvoid: <-- ENTER APIKEY HERE --><br>
shodan: <-- ENTER APIKEY HERE --><br>
passivetotal: <-- ENTER API KEY HERE -->

# TODO
* Get ShodanAPI working in iposint.py
* Add ShadowServer functionality into OSINT tools
* Add AlienVault OTX API into iposint
* Get valid_ip function to work

# UPDATES
* Added PassiveTotal Passive DNS Resolution <br>
* Removed ShodanAPI, will re-add after more testing