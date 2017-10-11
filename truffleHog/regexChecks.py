import re

regexes = {
    "Internal subdomain": re.compile('([a-z0-9]+[.]*supersecretinternal[.]com)'),
    "Slack Token": re.compile('(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})'),
    "RSA private key": re.compile('-----BEGIN RSA PRIVATE KEY-----'),
    "Facebook Oauth": re.compile('[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*[0-9a-f]{32}'),
    "Twitter Oauth": re.compile('[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[0-9a-zA-Z]{35,44}'),
    "Google Oauth": re.compile('("client_secret":"[a-zA-Z0-9-_]{24}")'),
    "AWS API Key": re.compile('[a|A][w|W][s|S].*AKIA[0-9A-Z]{16}')
}

