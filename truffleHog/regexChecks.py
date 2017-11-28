import re

regexes = {
    # "Internal subdomain": re.compile('([a-z0-9]+[.]*supersecretinternal[.]com)'),
    "Slack Token": re.compile(r'(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})'),
    "RSA private key": re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
    # "Facebook Oauth": re.compile('[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*[\'|"][0-9a-f]{32}[\'|"]'),
    "Facebook Oauth": re.compile(r'(?i:facebook).*[\'"][0-9a-f]{32}[\'"]'),
    # "Twitter Oauth": re.compile('[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*[\'|"][0-9a-zA-Z]{35,44}[\'|"]'),
    "Twitter Oauth": re.compile(r'twitter.*[\'"][a-z0-9]{35,44}[\'"]', re.I),
    "Google Oauth": re.compile(r'"client_secret"\s*:\s*"[\w\-]{24}"'),
    "AWS API Key": re.compile(r'AKIA[0-9A-Z]{16}'),#[a|A][w|W][s|S].*AKIA[0-9A-Z]{16}'),
    # "Heroku API Key": re.compile('[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}'),
    "Heroku API Key": re.compile(r'(?i:heroku).*[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}'),
    # "Generic Secret": re.compile('[s|S][e|E][c|C][r|R][e|E][t|T].*[\'|"][0-9a-zA-Z]{32,45}[\'|"]')
}

