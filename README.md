# vuln-parameters
This script is used for finding possibly vulnerable parameters on a target domain, saving the found urls in a file for further enumeration.
It utilizes the wayback machine to get all crawled urls of the specified domain and subdomains. This tool uses the wayback machine to avoid captcha issues from multiple requests to google, slow responses etc. Since multiple urls are already stored in the webarchive, we bypass intermediate issues.

# Setup - Clone the Repo
First, clone the repo:
```
git clone https://github.com/connar/vuln-parameters.git
cd vuln-parameters
```

# Setup - Install dependencies
After cloning the repo, install the dependencies that the script has:
```
pip install -r requirements.txt
```
Also, we need the  `uro` utility for further parsing of urls after getting them from the wayback machine:  
```
git clone https://github.com/s0md3v/uro.git
cd uro
python setup.py install
cp uro/uro.py /usr/bin
cp uro/uro.py /usr/sbin
```

# Run the script
After setting up the script, it can be run as:
```
python vuln-parameters.py --domain <domain_name> --size <size_in_MB>
```

# Example
The following is an example output targeting the example.com:
```sh
└─$ python vuln-parameters.py --domain example.com --size 5000
Fetching URLs for *.example.com/* ...
[+] Downloading URLs: URLs fetched successfully
[+] Data downloaded: Total downloaded: 5120285 bytes
Running uro to deduplicate and clean URLs...
[+] Processing URLs with uro: Processed 13735 unique URLs

Parameter Occurrences in URLs with Vulnerabilities:
+------------------------+---------------+
| Vulnerable Parameter   |   Occurrences |
+========================+===============+
| page                   |            36 |
+------------------------+---------------+
| q                      |            70 |
+------------------------+---------------+
| reset                  |             1 |
+------------------------+---------------+
| template               |             3 |
+------------------------+---------------+
| search                 |             9 |
+------------------------+---------------+
| lang                   |            20 |
+------------------------+---------------+
| cat                    |            15 |
...
...
Vulnerable URLs saved to vuln_param_urls.txt.

└─$ cat vuln_param_urls.txt | grep "cat="
http://www.example.com/%E2%80%8Basp%E2%80%8B/sp.asp?cat=%E2%80%8B12&amp;id=1030
https://www.example.com/?cat=-123&feed=rss2Older
http://www.example.com:80/?cat=42&feed=rss2
http://www.example.com:80/?cat=4
...
...
```
