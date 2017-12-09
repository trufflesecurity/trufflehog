import re

regexes = {
    "Slack Token": re.compile(r'(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})'),
    "RSA private key": re.compile(r'-----BEGIN RSA PRIVATE KEY-----'),
    "Facebook Oauth": re.compile(r'(?i:facebook).*[\'"][0-9a-f]{32}[\'"]'),
    "Twitter Oauth": re.compile(r'twitter.*[\'"][a-z0-9]{35,44}[\'"]', re.I),
    "Google Oauth": re.compile(r'"client_secret"\s*:\s*"[\w\-]{24}"'),
    "AWS API Key": re.compile(r'AKIA[0-9A-Z]{16}'),  # [aA][wW][sS].*AKIA[0-9A-Z]{16}'),
    "Heroku API Key": re.compile(r'(?i:heroku).*[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}'),
}
