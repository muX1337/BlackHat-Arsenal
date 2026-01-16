# DNS Reaper

## Description
DNS Reaper is yet another sub-domain takeover tool, but with an emphasis on accuracy, speed, and the number of signatures in our arsenal!

We can scan around 50 subdomains per second, testing each one with over 50 takeover signatures. This means most organizations can scan their entire DNS estate in less than 10 seconds.

You can use DNS Reaper as an attacker or bug hunter!
You can run it by providing a list of domains in a file, or a single domain on the command line. DNS Reaper will then scan the domains with all of its signatures, producing a CSV file.

You can use DNS Reaper as a defender!
You can run it by letting it fetch your DNS records for you! Yes, that's right, you can run it with credentials and test all your domain configurations quickly and easily. DNS Reaper will connect to the DNS provider and fetch all your records, and then test them.

We currently support AWS Route53, Cloudflare, and Azure.

## Code
https://github.com/punk-security/dnsReaper
