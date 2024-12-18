# Ingest Phish as Structured Incident Response Cases into OpenCTI

An example script that can parse phishing emails (raw ASCII or UTF-8
MSG files) and ingest them into OpenCTI using
[`pycti`](https://github.com/OpenCTI-Platform/client-python).

Usage:
```sh
# Install dependencies
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Edit the local_settings.py for your own server
cp local_settings.py.example local_settings.py
vim local_settings.py  # or, your favorite editor

# Ingest emails
python ./import_email.py /path/to/your/emails/*.msg
```

This tool will use the Python [`email`](https://docs.python.org/3/library/email.examples.html)
module to parse each email specified in the list on the command-line, and create cases for them
comprised of one or more of the following contained objects:
* Incident
* Email
* Email address
* Domain name
* IPv4 address
* IPv6 address
* Url
* Attachments

# Getting Phish

Many places to get phish.

I tested it on the following dataset:
* https://github.com/rf-peixoto/phishing_pot
