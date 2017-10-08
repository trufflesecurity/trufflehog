import re

regexes = {
    "Internal subdomain": re.compile('([a-z0-9]+[.]*supersecretinternal[.]com)'),
    "Slack Token": re.compile('(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})'),
    "Google Oauth": re.compile('("client_secret":"[a-zA-Z0-9-_]{24}")'),
    "RSA private key": re.compile('-----BEGIN RSA PRIVATE KEY-----')
}

