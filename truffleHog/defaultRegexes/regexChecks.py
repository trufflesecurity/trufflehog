import re

regexes = {
    #"Internal subdomain": re.compile('([a-z0-9]+[.]*supersecretinternal[.]com)'),
    "Slack Token": re.compile('(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})'),
    "RSA private key": re.compile('-----BEGIN RSA PRIVATE KEY-----'),
    "SSH (OPENSSH) private key": re.compile('-----BEGIN OPENSSH PRIVATE KEY-----'),
    "SSH (DSA) private key": re.compile('-----BEGIN DSA PRIVATE KEY-----'),
    "SSH (EC) private key": re.compile('-----BEGIN EC PRIVATE KEY-----'),
    "PGP private key block": re.compile('-----BEGIN PGP PRIVATE KEY BLOCK-----'),
    "Facebook Oauth": re.compile('[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*[\'|"][0-9a-f]{32}[\'|"]'),
    "Twitter Oauth": re.compile('[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[\'|"][0-9a-zA-Z]{35,44}[\'|"]'),
    "GitHub": re.compile('[g|G][i|I][t|T][h|H][u|U][b|B].*[[\'|"]0-9a-zA-Z]{35,40}[\'|"]'),
    "Google Oauth": re.compile('("client_secret":"[a-zA-Z0-9-_]{24}")'),
    "AWS API Key": re.compile('AKIA[0-9A-Z]{16}'),
    "Heroku API Key": re.compile('[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}'),
    "Generic Secret": re.compile('[s|S][e|E][c|C][r|R][e|E][t|T].*[\'|"][0-9a-zA-Z]{32,45}[\'|"]'),
}

