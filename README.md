# Vision
Nmap's XML parse and NVD CPE correlation with CVE

```
	..::: VISION v0.1 :::... 
        Nmap\'s XML result parser and NVD's CPE correlation to search CVE
	
	Example:
		python vision.py result_scan.xml 3 txt
	argv 1 = Nmap scanner results in XML
	argv 2 = Limit CVEs per CPE to get
	argv 3 = Type of output (xml or txt)
```

Example of results:
```
$ python Vision-cpe.py result_nmap.xml 3 txt

::::: Vision v0.1 - nmap NVD's cpe correlation - Coded by CoolerVoid

PORT: 53
cpe:/a:isc:bind:9.8.1:p1

	URL: https://nvd.nist.gov/vuln/detail/CVE-2016-9131
	Description: named in ISC BIND 9.x before 9.9.9-P5, 9.10.x before 9.10.4-P5, and 9.11.x before 9.11.0-P2 allows remote attackers to cause a denial of service (assertion failure and daemon exit) via a malformed response to an RTYPE ANY query.

	URL: https://nvd.nist.gov/vuln/detail/CVE-2016-8864
	Description: named in ISC BIND 9.x before 9.9.9-P4, 9.10.x before 9.10.4-P4, and 9.11.x before 9.11.0-P1 allows remote attackers to cause a denial of service (assertion failure and daemon exit) via a DNAME record in the answer section of a response to a recursive query, related to db.c and resolver.c.

	URL: https://nvd.nist.gov/vuln/detail/CVE-2016-2848
	Description: ISC BIND 9.1.0 through 9.8.4-P2 and 9.9.0 through 9.9.2-P2 allows remote attackers to cause a denial of service (assertion failure and daemon exit) via malformed options data in an OPT resource record.


```
