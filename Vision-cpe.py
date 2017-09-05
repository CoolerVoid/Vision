#!/usr/bin/python

import xml.etree.ElementTree as treant
import requests, sys
import warnings

warnings.simplefilter("ignore")

def banner_vision():
 print """		..::: VISION v0.1 :::... 
        Nmap\'s XML result parser and NVD's CPE correlation to search CVE
	
	Example:
		python vision.py result_scan.xml 3 txt

	argv 1 = Nmap scanner results in XML
	argv 2 = Limit CVEs per CPE to get
	argv 3 = Type of output (xml or txt)

											Coded by CoolerVoid  
"""

def fix_cpe_str(str):
 str=str.replace('-',':')
 return str

def txtoutput(r,port,cpe,limit):
	print "PORT: "+port
	print cpe+"\n"
	counter=2
	for line in r.iter_lines():
    		if line and limit != 0:	 
			if line.find("<strong><a href=\"/vuln/detail/")>1:
				cve=line.split('"')
				cve_url="https://nvd.nist.gov"+cve[1]
				print "\tURL: "+cve_url
				counter-=1	
			if line.find("data-testid='vuln-summary-")>1:
				desc_parse=line.split('>')
				description=desc_parse[1][:-3]
				print "\tDescription: "+description+"\n"
				counter-=1
			if counter == 0:
				limit-=1
				counter=2
	return;

def xmloutput(r,port,cpe,limit):
	print "\n<vision>\n<port>"+port+"</port>\n"
	print "<cpe>"+cpe+"</cpe>\n"
	counter=2
	for line2 in r.iter_lines():
    		if line2 and limit != 0: 
			if line2.find("<strong><a href=\"/vuln/detail/")>1:
				cve=line2.split('"')
				cve_url="https://nvd.nist.gov"+cve[1]
				print "\r<cve> "+cve_url+"</cve>\n"
				counter-=1	
			if line2.find("data-testid='vuln-summary-")>1:
				desc_parse=line2.split('>')
				description=desc_parse[1][:-3]
				print "\r<description> "+description+"</description>\n"
				counter-=1
			if counter == 0:
				limit-=1
				counter=2
	print "</vision>"
	return


try:
 if len(sys.argv)==4:
 	tree = treant.parse(sys.argv[1])	
	root = tree.getroot()
	limit=int(sys.argv[2])
	type_output=sys.argv[3]
	counter=1

	if len(type_output)>3:
		print "Error: choice one output type, xml or txt...\n"
		exit(0)

	for child in root.findall('host'):
		for y in child.findall('ports/port'):		
			current_port=y.attrib['portid']
			for z in child.findall('ports/port/service/cpe'):
				if len(z.text)>4:
					cpe=fix_cpe_str(z.text)
					print "\n::::: Vision v0.1 - nmap NVD's cpe correlation - Coded by CoolerVoid\n"
					URL_mount="https://nvd.nist.gov/vuln/search/results?adv_search=true&cpe="+cpe
					r = requests.get(URL_mount,stream=True)
					if(r.status_code == 200):
						if type_output.find('txt',3) and counter == 1:
							txtoutput(r,current_port,cpe,limit)
							counter=0

						if type_output.find('xml',3) and counter ==1:
							xmloutput(r,current_port,cpe,limit)

						counter=1;
					else:
						print "\n Problem in NVD NIST server\n"
						exit(0)
					z.text=""
 else:
	print "\nError needs nmap's XML scan result by passed by first argument\n"
	print banner_vision()

except NameError:
 print "\nError\n Here! \n"
 sys.exit(0)
