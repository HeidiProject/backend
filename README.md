# Heidi backend server

Gunicorn Flask REST-API for Heidi interactions with the macromolecular crystallography (MX) mongo DB. 

Note: Authentication moving to MFA system for access to the Heidi web application.

## Authentication & Authorization: 

LDAP/MFA authentication handled by F5 BIG-IP. HTTPS traffic for webserver limited to only F5 server with iptables.

NGINX reverse proxy modified to forward `X-USERNAME` and `X-PGROUPS` from F5 after MFA has been successful and `server.py` is now refactored to accept and use this information. 

# MFA microsoft authenticator instructions for PSI

https://www.psi.ch/en/computing/change-to-mfa
