Let's Encrypt Cert Manager
==========================

* Use the Let's Encrypt `certbot` tool to request and renew certificates
* The user should be able to run the tool directly to request new certificates
* The tool should be easy to integrate into a daily cron job to run renewals
* DNS based authorization for `certbot`, supporting:
    * Cloudflare DNS API
    * Dreamhost DNS API
    * Google CloudDNS
    * AWS Route 53
    * DNS Made Easy
* Support DNS aliases in requests
* Support both staging and production certificates
    * Encourage user to create a staging certificate before switching to production
