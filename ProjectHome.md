**Java-google-safe-browsing** allows to check if a domain is known as malicious (hosts phishing or malware) using the Google Safe Browsing's database

You can find out more at http://code.google.com/apis/safebrowsing/

It contains two parts :
The Crawler which downloads datas from GSB and fills a database;
The Analyzer uses the database to check if domains are malicious or not.

Results tells if a domain hosts phishing or malware.