import os
import re
import time
import logging
import xml.etree.ElementTree as ET
from argparse import ArgumentParser
from xml.etree.ElementTree import ParseError

def merge_nMap(xmlFile,mf):
	HOSTS = 0
	with open(mf, mode = 'a', encoding='utf-8') as mergFile:
		with open(xmlFile) as f:
			nMapXML = ET.parse(f)
			for host in nMapXML.findall('host'):
				HOSTS = HOSTS + 1
				cHost = ET.tostring(host, encoding='unicode', method='xml') 
				mergFile.write(cHost)
				mergFile.flush()	
	return HOSTS

def addHeader(f):
	nMap_Header  = '<?xml version="1.0" encoding="UTF-8"?>'
	nMap_Header += '<!DOCTYPE nmaprun>'
	nMap_Header += '<?xml-stylesheet href="file:///usr/share/nmap/nmap.xsl" type="text/xsl"?>'
	nMap_Header += '<!-- Nmap Merged with nMapMergER.py https://github.com/CBHue/nMapMergER -->'
	nMap_Header += '<nmaprun scanner="nmap" args="nmap -iL hostList.txt" start="1" startstr="https://github.com/CBHue/nMapMerge/nMapMerge.py" version="7.70" xmloutputversion="1.04">'
	nMap_Header += '<scaninfo type="syn" protocol="tcp" numservices="1" services="1"/>'
	nMap_Header += '<verbose level="0"/>'
	nMap_Header += '<debugging level="0"/>'

	mFile = open(f, "w")  
	mFile.write(nMap_Header) 
	mFile.close()

def addFooter(f, h):
	nMap_Footer  = '<runstats><finished time="1" timestr="Wed Sep  0 00:00:00 0000" elapsed="0" summary="Nmap done at Wed Sep  0 00:00:00 0000; ' + str(h) + ' IP address scanned in 0.0 seconds" exit="success"/>'
	nMap_Footer += '</runstats>'
	nMap_Footer += '</nmaprun>'

	mFile = open(f, "a")  
	mFile.write(nMap_Footer) 
	mFile.close()

#
# If you want to use this as a module you need to pass a set of nmap xmls
#
# nmapSET = set()
# nmapSET.add('/nmap-Dir/nmap_10.10.10.10.xml')
#
# Then call the main function passing the set:
# main_nMapMerger(nmapSET)
#
def main_nmap_merger(xmlSet, directory):
	HOSTS = 0

	# Check to ensute we have work to do
	if not xmlSet:
		#print("No XML files were found ... No work to do")
		return False

	# Create the Merged filename
	from datetime import datetime
	dtNow = datetime.now() 
	dt = re.sub(r"\s+", '-', str(dtNow))
	dt = re.sub(r":", '-', str(dt))
	merge_name = "merged_" + dt + ".xml"
	merge_file = os.path.join(directory, merge_name)

	# Add Header to mergefile
	addHeader(merge_file)

	for xml in xmlSet:
		if xml.endswith('.xml'):
			#logging.debug("Parsing: %r", xml)
			H = merge_nMap(xml,merge_file)
			HOSTS = HOSTS + H

	# Add Footer to mergefile
	addFooter(merge_file, HOSTS)
	return os.path.abspath(merge_file)