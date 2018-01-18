import re

regexes = {
    #"Internal subdomain": re.compile('([a-z0-9]+[.]*supersecretinternal[.]com)'),
    "Slack Token": re.compile('(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})'),
    "RSA private key": re.compile('-----BEGIN RSA PRIVATE KEY-----'),
    "SSH (OPENSSH) private key": re.compile('-----BEGIN OPENSSH PRIVATE KEY-----'),
    "SSH (DSA) private key": re.compile('-----BEGIN DSA PRIVATE KEY-----'),
    "SSH (EC) private key": re.compile('-----BEGIN EC PRIVATE KEY-----'),
    "PGP private key block": re.compile('-----BEGIN PGP PRIVATE KEY BLOCK-----'),
    "Facebook Oauth": re.compile('facebook.*[\'|"][0-9a-f]{32}[\'|"]', re.I),
    "Twitter Oauth": re.compile('twitter.*[\'|"][0-9a-z]{35,44}[\'|"]', re.I),
    "GitHub": re.compile('github.*[[\'|"]0-9a-z]{35,40}[\'|"]', re.I),
    "Google Oauth": re.compile('("client_secret":"[a-z0-9-_]{24}")', re.I),
    "AWS API Key": re.compile('AKIA[0-9A-Z]{16}'),
    "Heroku API Key": re.compile('[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}'),
    "Generic Secret": re.compile('secret.*[\'|"][0-9a-z]{32,45}[\'|"]', re.I),
}
