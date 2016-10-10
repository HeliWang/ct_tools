# All configuration for the CT monitor is done from this file!

# interval (in seconds) between updates
INTERVAL = 60 

# Directories for various output files
OUTPUT_DIR = "output/"

# Output file for certificate data.
# Set to None to disable textfile writing
DEFAULT_CERT_FILE = None
# DEFAULT_CERT_FILE = OUTPUT_DIR + "cert_data.json"

# Set to None to disable database writing
# DOMAINS_FILE = OUTPUT_DIR + "domains.json"
DOMAINS_FILE = None
ISSUERS_FILE = DOMAINS_FILE = OUTPUT_DIR + "issuers.log"

# Set to None to disable database output
# DB_PATH = './tmpdb/'
DB_PATH = None

MONITORED_DOMAINS = [
    "*.liu.se",
    "*.kth.se",
    "*.nordu.net",
    "*.sunet.se",
    "*.dfri.se",
    "*.iis.se",
]

MONITORED_ISSUERS = [
    "Let's Encrypt",
]

# Some strings
ERROR_STR = "ERROR: "

# CT logs and associated keys
CTLOGS = [
    {"name" : "pilot",
    "url" : "https://ct.googleapis.com/pilot/",
    "key" : "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfahLEimAoz2t01p3uMziiLOl/fHTDM0YDOhBRuiBARsV4UvxG2LdNgoIGLrtCzWE0J5APC2em4JlvR8EEEFMoA==",
    "id" : "pLkJkLQYWBSHuxOizGdwCjw1mAT5G9+443fNDsgN3BA=",
    "build" : False},

    {"name" : "plausible",
    "url" : "https://plausible.ct.nordu.net/",
    "key" : "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE9UV9+jO2MCTzkabodO2F7LM03MUBc8MrdAtkcW6v6GA9taTTw9QJqofm0BbdAsbtJL/unyEf0zIkRgXjjzaYqQ==",
    "id" : "qucLfzy41WbIbC8Wl5yfRF9pqw60U1WJsvd6AwEE880=",
    "build" : True},

    {"name" : "digicert",
    "url" : "https://ct1.digicert-ct.com/log/",
    "key" : "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAkbFvhu7gkAW6MHSrBlpE1n4+HCFRkC5OLAjgqhkTH+/uzSfSl8ois8ZxAD2NgaTZe1M9akhYlrYkes4JECs6A==",
    "id" : "VhQGmi/XwuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ0N0=",
    "build" : False},

    {"name" : "izenpe",
    "url" : "https://ct.izenpe.com/",
    "key" : "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJ2Q5DC3cUBj4IQCiDu0s6j51up+TZAkAEcQRF6tczw90rLWXkJMAW7jr9yc92bIKgV8vDXU4lDeZHvYHduDuvg==",
    "id" : "dGG0oJz7PUHXUVlXWy52SaRFqNJ3CbDMVkpkgrfrQaM=",
    "build" : False},
    
    {"name" : "certly",
    "url" : "https://log.certly.io/",
    "key" : "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECyPLhWKYYUgEc+tUXfPQB4wtGS2MNvXrjwFCCnyYJifBtd2Sk7Cu+Js9DNhMTh35FftHaHu6ZrclnNBKwmbbSA==",
    "id" : "zbUXm3/BwEb+6jETaj+PAC5hgvr4iW/syLL1tatgSQA=",
    "build" : False}, 

    {"name" : "aviator",
    "url" : "https://ct.googleapis.com/aviator/",
    "key" : "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1/TMabLkDpCjiupacAlP7xNi0I1JYP8bQFAHDG1xhtolSY1l4QgNRzRrvSe8liE+NPWHdjGxfx3JhTsN9x8/6Q==",
    "id" : "aPaY+B9kgr46jO65KB1M/HFRXWeT1ETRCmesu09P+8Q=",
    "build" : False},

    {"name" : "rocketeer",
    "url" : "https://ct.googleapis.com/rocketeer/",
    "key" : "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIFsYyDzBi7MxCAC/oJBXK7dHjG+1aLCOkHjpoHPqTyghLpzA9BYbqvnV16mAw04vUjyYASVGJCUoI3ctBcJAeg==",
    "id": "7ku9t3XOYLrhQmkfq+GeZqMPfl+wctiDAMR7iXqo/cs=",
    "build" : False},

    {"name" : "symantec",
    "url" : "https://ct.ws.symantec.com/",
    "key" : "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEluqsHEYMG1XcDfy1lCdGV0JwOmkY4r87xNuroPS2bMBTP01CEDPwWJePa75y9CrsHEKqAy8afig1dpkIPSEUhg==",
    "id" : "3esdK3oNT6Ygi4GtgWhwfi6OnQHVXIiNPRHEzbbsvsw=",
    "build" : False},
    
    {"name" : "venafi",
    "url" : "https://ctlog.api.venafi.com/",
    "key" : "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAolpIHxdSlTXLo1s6H1OCdpSj/4DyHDc8wLG9wVmLqy1lk9fz4ATVmm+/1iN2Nk8jmctUKK2MFUtlWXZBSpym97M7frGlSaQXUWyA3CqQUEuIJOmlEjKTBEiQAvpfDjCHjlV2Be4qTM6jamkJbiWtgnYPhJL6ONaGTiSPm7Byy57iaz/hbckldSOIoRhYBiMzeNoA0DiRZ9KmfSeXZ1rB8y8X5urSW+iBzf2SaOfzBvDpcoTuAaWx2DPazoOl28fP1hZ+kHUYvxbcMjttjauCFx+JII0dmuZNIwjfeG/GBb9frpSX219k1O4Wi6OEbHEr8at/XQ0y7gTikOxBn/s5wQIDAQAB",
    "id" : "rDua7X+pZ0dXFZ5tfVdWcvnZgQCUHpve/+yhMTt1eC0=",
    "build" : False},

    {"name" : "wosign",
    "url" : "https://ct.wosign.com/",
    "key" : "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1+wvK3VPN7yjQ7qLZWY8fWrlDCqmwuUm/gx9TnzwOrzi0yLcAdAfbkOcXG6DrZwV9sSNYLUdu6NiaX7rp6oBmw==",
    "id" : "nk/3PcPOIgtpIXyJnkaAdqv414Y21cz8haMadWKLqIs=",
    "build" : False},    

]




