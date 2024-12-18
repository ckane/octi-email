#!/usr/bin/env python
import logging
from msticpy.transform import IoCExtract
import re
import urllib3
from datetime import datetime, UTC
from dateutil.parser import parse as dateparse
from argparse import ArgumentParser, BooleanOptionalAction
from email.parser import BytesParser as EmailBytesParser
from email.policy import default as default_email_policy
from pycti import OpenCTIApiClient

from local_settings import octi_url, octi_token

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def sanitize_content(data):
    if not data:
        return data

    # Return an arbitrarily sanitized/redacted copy of input data
    # data = data.replace('sensitive data', 'REDACTED')
    return data


def filter_ipv4_defects(data):
    # Only accept real IPs
    for x in data.split('.'):
        try:
            if int(x) < 0 or int(x) > 255:
                # All octets need to be [0, 255]
                return False
        except:
            # Not a number
            return False

    return True

def filter_ipv6_defects(data):
    # Don't confuse time w/ or w/out seconds
    if len(data.split(':')) in [2, 3]:
        return False

    return True

def filter_url_defects(data):
    # Bad chars, or no pathsep
    if data.find('>') >= 0 or data.find('<') >= 0 or data.find('/') < 0:
        return False

    return True

def filter_dns_defects(data):
    # Bad extensions
    if re.compile(r'\.(png|gif|jpg|html|htm)$').search(data):
        return False

    if data.find('>') >= 0 or data.find('<') >= 0:
        return False

    return True

class EmailIngest(object):
    def __init__(self, msg, args):
        self.octi = OpenCTIApiClient(octi_url, octi_token)
        self.msg = EmailBytesParser(policy=default_email_policy).parse(fp=open(msg, 'rb'))
        self.args = args
        self.dns_re = re.compile(r'[A-Za-z0-9][A-Za-z0-9-.]*\.[a-z]{2,4}')
        self.green = self.octi.marking_definition.read(filters={
            'mode': 'and',
            'filters': [{
                'key': 'definition',
                'values': ['TLP:GREEN'],
                'operator': 'eq',
                'mode': 'and',
            }, {
                'key': 'definition_type',
                'values': ['TLP'],
                'operator': 'eq',
                'mode': 'and',
            }],
            'filterGroups': [],
        })['id']
        self.clear = self.octi.marking_definition.read(filters={
            'mode': 'and',
            'filters': [{
                'key': 'definition',
                'values': ['TLP:CLEAR'],
                'operator': 'eq',
                'mode': 'and',
            }, {
                'key': 'definition_type',
                'values': ['TLP'],
                'operator': 'eq',
                'mode': 'and',
            }],
            'filterGroups': [],
        })['id']
        self.myself = self.octi.identity.create(
            type = 'Individual',
            name = 'Coleman Kane',
            objectMarking = self.clear,
            contact_information = 'cincykane@gmail.com',
            x_opencti_firstname = 'Coleman',
            x_opencti_lastname = 'Kane',
            update = self.args.update,
        )['id']

    def parse_incident(self):
        inc = {
            'stix_id': self.octi.incident.generate_id(self.msg['message-id'] if self.msg['message-id'] != None else 'NO-MSG-ID',
                                                      self.msg['date'] if self.msg['date'] != None else 'NO-DATE'),
            'objectMarking': self.green,
            'confidence': 80,
            'createdBy': self.myself,
            'lang': 'en',
            'created': dateparse(self.msg['date']).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'modified': datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ'),
            'name': 'Phish: "{}"'.format(self.msg['Subject']),
            'incident_type': 'phishing',
            'severity': 'low',
            'source': '',
            'description': 'Phishing message',
            'update': self.args.update,
        }
        inc['first_seen'] = inc['last_seen'] = inc['created']
        self.inc_json = inc
        self.inc = self.octi.incident.create(**inc)

    def parse_email(self, rhs):
        mid = sanitize_content(self.msg['message-id'])

        body = ""
        for btype in ['plain', 'html']:
            try:
                body = self.msg.get_body(preferencelist=(btype,)).get_content()
            except:
                try:
                    body = self.msg.get_body(preferencelist=(btype,))
                except:
                    pass

            if body:
                break

        adjdate = dateparse(self.msg['date']).strftime('%Y-%m-%dT%H:%M:%SZ')
        email = {
            'observableData': {
                'is_multipart': self.msg.is_multipart(),
                'date': adjdate,
                'type': 'Email-Message',
                'message_id': mid,
                'subject': str(self.msg['subject']),
                'received_lines': rhs,
                'body': body,
            },
            'createdBy': self.myself,
            'objectMarking': self.green,
            'update': self.args.update,
        }
        self.email = self.octi.stix_cyber_observable.create(**email)

        body_objs = []
        if body:
            ioc = {}
            try:
                iocs = IoCExtract().extract(body)
                for ipv4 in filter(filter_ipv4_defects, iocs['ipv4']):
                    ip = {
                        'observableData': {
                            'value': ipv4,
                            'type': 'IPv4-Addr',
                        },
                        'objectMarking': self.green,
                        'createdBy': self.myself,
                        'update': self.args.update,
                    }
                    try:
                        i = self.octi.stix_cyber_observable.create(**ip)
                        body_objs.append(i)
                    except:
                        log.error('Failed IOC upload: {ioc}'.format(ioc=ip))

                for ipv6 in filter(filter_ipv6_defects, iocs['ipv6']):
                    ip = {
                        'observableData': {
                            'value': ipv6,
                            'type': 'IPv6-Addr',
                        },
                        'objectMarking': self.green,
                        'createdBy': self.myself,
                        'update': self.args.update,
                    }
                    try:
                        i = self.octi.stix_cyber_observable.create(**ip)
                        body_objs.append(i)
                    except:
                        log.error('Failed IOC upload: {ioc}'.format(ioc=ip))

                for em in iocs['email']:
                    ea = {
                        'observableData': {
                            'value': em,
                            'type': 'Email-Addr',
                        },
                        'objectMarking': self.green,
                        'createdBy': self.myself,
                        'update': self.args.update,
                    }
                    try:
                        e = self.octi.stix_cyber_observable.create(**ea)
                        body_objs.append(e)
                    except:
                        log.error('Failed IOC upload: {ioc}'.format(ioc=ea))

                for urlstr in filter(filter_url_defects, iocs['url']):
                    url = {
                        'observableData': {
                            'value': urlstr,
                            'type': 'Url',
                        },
                        'objectMarking': self.green,
                        'createdBy': self.myself,
                        'update': self.args.update,
                    }
                    try:
                        u = self.octi.stix_cyber_observable.create(**url)
                        body_objs.append(u)
                    except:
                        log.error('Failed IOC upload: {ioc}'.format(ioc=url))

                for dom in filter(filter_dns_defects, iocs['dns']):
                    domain = {
                        'observableData': {
                            'value': dom,
                            'type': 'Domain-Name',
                        },
                        'objectMarking': self.green,
                        'createdBy': self.myself,
                        'update': self.args.update,
                    }
                    try:
                        d = self.octi.stix_cyber_observable.create(**domain)
                        body_objs.append(d)
                    except:
                        log.error('Failed IOC upload: {ioc}'.format(ioc=domain))
            except:
                log.error('Couldn\'t parse body')

        self.body_objs = body_objs

    def parse_case(self):
        case = self.inc_json.copy()
        case['stix_id'] = 'case-' + case['stix_id']
        del case['first_seen']
        del case['last_seen']
        del case['incident_type']
        del case['source']
        objects = [self.inc['id']]
        objects.extend(x['id'] for x in self.stix_objs)
        objects.extend(x['id'] for x in self.stix_rels)
        case['objects'] = objects
        self.case = self.octi.case_incident.create(**case)

    def parse_stix_objs(self):
        stix_objs = []
        stix_rels = []

        # Parse out sender emails
        for hdr in ['from', 'reply-to', 'return-path']:
            if hdr in self.msg and self.msg[hdr] != None:
                if hasattr(self.msg[hdr], 'addresses'):
                    for addr in self.msg[hdr].addresses:
                        if re.compile(r'[a-zA-Z0-9\.\+\-\_]+@[a-zA-Z0-9\.\-]+').search(addr.addr_spec):
                            email_addr = {
                                'observableData': {
                                    'value': addr.addr_spec,
                                    'display_name': addr.display_name,
                                    'type': 'Email-Addr',
                                },
                                'createdBy': self.myself,
                                'objectMarking': self.green,
                                'update': self.args.update,
                            }
                            try:
                                e = self.octi.stix_cyber_observable.create(**email_addr)
                                stix_objs.append(e)
                            except:
                                log.error('Failed IOC upload: {ioc}'.format(ioc=email_addr))

                            domain_name = {
                                'observableData': {
                                    'value': addr.domain,
                                    'type': 'Domain-Name',
                                },
                                'createdBy': self.myself,
                                'objectMarking': self.green,
                                'update': self.args.update,
                            }
                            try:
                                d = self.octi.stix_cyber_observable.create(**domain_name)
                                stix_objs.append(d)

                                rel = {
                                    'toId': e['id'],
                                    'fromId': d['id'],
                                    'relationship_type': 'related-to',
                                    'objectMarking': self.green,
                                    'confidence': 80,
                                    'description': 'Derived domain-name from email address',
                                    'createdBy': self.myself,
                                    'update': self.args.update,
                                }
                                try:
                                    r = self.octi.stix_core_relationship.create(**rel)
                                    stix_rels.append(r)
                                except:
                                    log.error('Failed relationship upload: {rel}'.format(rel=rel))
                            except:
                                log.error('Failed IOC upload: {ioc}'.format(ioc=domain_name))

        # Parse out Received: headers
        rhs = []
        for rh in (sanitize_content(r) for r in self.msg.get_all('Received')):
            if not rh:
                continue
            rhs.append(rh)
            iocs = IoCExtract().extract(rh)
            for ipv4 in filter(filter_ipv4_defects, iocs['ipv4']):
                ip = {
                    'observableData': {
                        'value': ipv4,
                        'type': 'IPv4-Addr',
                    },
                    'objectMarking': self.green,
                    'createdBy': self.myself,
                    'update': self.args.update,
                }
                try:
                    i = self.octi.stix_cyber_observable.create(**ip)
                    stix_objs.append(i)
                except:
                    log.error('Failed IOC upload: {ioc}'.format(ioc=ip))


            for ipv6 in filter(filter_ipv6_defects, iocs['ipv6']):
                ip = {
                    'observableData': {
                        'value': ipv6,
                        'type': 'IPv6-Addr',
                    },
                    'objectMarking': self.green,
                    'createdBy': self.myself,
                    'update': self.args.update,
                }
                try:
                    i = self.octi.stix_cyber_observable.create(**ip)
                    stix_objs.append(i)
                except:
                    log.error('Failed IOC upload: {ioc}'.format(ioc=ip))

            for em in iocs['email']:
                ea = {
                    'observableData': {
                        'value': em,
                        'type': 'Email-Addr',
                    },
                    'objectMarking': self.green,
                    'createdBy': self.myself,
                    'update': self.args.update,
                }
                try:
                    e = self.octi.stix_cyber_observable.create(**ea)
                    stix_objs.append(e)
                except:
                    log.error('Failed IOC upload: {ioc}'.format(ioc=ea))

            for urlstr in filter(filter_url_defects, iocs['url']):
                url = {
                    'observableData': {
                        'value': urlstr,
                        'type': 'Url',
                    },
                    'objectMarking': self.green,
                    'createdBy': self.myself,
                    'update': self.args.update,
                }
                try:
                    u = self.octi.stix_cyber_observable.create(**url)
                    stix_objs.append(u)
                except:
                    log.error('Failed IOC upload: {ioc}'.format(ioc=url))

            for dom in filter(filter_dns_defects, iocs['dns']):
                domain = {
                    'observableData': {
                        'value': dom,
                        'type': 'Domain-Name',
                    },
                    'objectMarking': self.green,
                    'createdBy': self.myself,
                    'update': self.args.update,
                }
                try:
                    d = self.octi.stix_cyber_observable.create(**domain)
                    stix_objs.append(d)
                except:
                    log.error('Failed IOC upload: {ioc}'.format(ioc=domain))

        self.parse_email(rhs)

        for a in self.msg.iter_attachments():
            artifact = {
                'file_name': a.get_filename(),
                'mime_type': a.get_content_type(),
                'data': a.get_content(),
                'x_opencti_description': 'Was attached to phishing email',
                'createdBy': self.myself,
                'objectMarking': self.green,
            }
            a = self.octi.stix_cyber_observable.upload_artifact(**artifact)
            stix_objs.append(a)

        stix_objs.extend(self.body_objs)

        for o in stix_objs:
            rel = {
                'toId': self.email['id'],
                'fromId': o['id'],
                'relationship_type': 'related-to',
                'objectMarking': self.green,
                'confidence': 100,
                'description': 'Found in email',
                'createdBy': self.myself,
                'update': self.args.update,
            }
            r = self.octi.stix_core_relationship.create(**rel)
            stix_rels.append(r)

        stix_objs.append(self.email)

        for o in stix_objs:
            rel = {
                'toId': self.inc['id'],
                'fromId': o['id'],
                'relationship_type': 'related-to',
                'objectMarking': self.green,
                'confidence': 100,
                'description': 'Found in email',
                'createdBy': self.myself,
                'update': self.args.update,
            }
            r = self.octi.stix_core_relationship.create(**rel)
            stix_rels.append(r)

        self.stix_objs = stix_objs
        self.stix_rels = stix_rels

    def ingest(self):
        self.parse_incident()
        self.parse_stix_objs()
        self.parse_case()

ap = ArgumentParser(description='parse emails into OCTI as incidents')
ap.add_argument('msg', nargs='+', help='Email msg files')
ap.add_argument('--update', '-u', action=BooleanOptionalAction, type=bool, default=False, help='Update existing entities')
args = ap.parse_args()

log = logging.getLogger(name='octi_email_import')
log.setLevel(logging.DEBUG)

for m in args.msg:
    log.info(f"Ingesting {m}...")
    EmailIngest(msg=m, args=args).ingest()
