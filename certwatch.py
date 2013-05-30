#!/usr/bin/python3
import re
import os
import hashlib
from datetime import datetime, timedelta
from calendar import timegm

from email.message import Message
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from wsgiref.handlers import format_date_time

import pyasn1
from pyasn1.codec.der import decoder, encoder
from pyasn1.type.useful import GeneralizedTime
import pyasn1_modules.pem as pem
import pyasn1_modules.rfc2459 as x509

CONFIG_TIMEDELTA_RE = re.compile("([0-9]+(.[0-9]*)?)\s*([a-zA-Z]+)")

def parse_certificate(fileobj):
    if isinstance(fileobj, str):
        fileobj = open(fileobj, "r")
        owns = True
    else:
        owns = False
    try:
        binary_data = pem.readPemFromFile(fileobj)
        decoded = decoder.decode(binary_data,
                                 asn1Spec=x509.Certificate())[0]

        hasher = hashlib.new("sha1")
        hasher.update(binary_data)
        fingerprint = hasher.hexdigest()

        return decoded, fingerprint
    finally:
        if owns:
            fileobj.close()

def parse_date(date):
    date = str(date)
    if isinstance(date, GeneralizedTime):
        return datetime.strptime(date, "%Y%m%d%H%M%SZ")
    else:
        return datetime.strptime(date, "%y%m%d%H%M%SZ")

def extract_validity(cert):
    tbs = cert.getComponentByName("tbsCertificate")
    validity = tbs.getComponentByName("validity")

    not_before = validity.getComponentByName("notBefore").getComponent()
    not_after = validity.getComponentByName("notAfter").getComponent()

    return parse_date(not_before), parse_date(not_after)

def get_ttl(validity):
    _, not_after = validity
    return not_after - datetime.utcnow()

def parse_config_timedelta(s):
    parsed = CONFIG_TIMEDELTA_RE.match(s)
    if parsed is None:
        raise ValueError("Not a valid time interval: {}".format(s))

    count, _, unit = parsed.groups()
    if unit.endswith("s") and unit != "s":
        unit = unit[:-1]
    count = float(count)

    days_factor = {
        "day": 1,
        "week": 7,
        "year": 365
    }.get(unit, 0)
    seconds_factor = {
        "minute": 60,
        "min": 60,
        "hour": 3600,
        "h": 3600,
        "s": 1,
        "second": 1
    }.get(unit, 0)

    if days_factor == 0 and seconds_factor == 0:
        raise ValueError("Unknown unit: {}".format(unit))

    return timedelta(days=count*days_factor,
                     seconds=count*seconds_factor)

def format_fingerprint(fingerprint):
    octets = int(len(fingerprint)/2)
    formatted = ""
    for octet_idx in range(octets):
        formatted += fingerprint[octet_idx*2:(octet_idx+1)*2] + ":"
    return formatted[:-1].upper()

def construct_warning_mail(responsible, warnlist, fromaddr):
            #~ mail = MIMEMultipart()
        #~ mail["To"] = self.configFile['mail']['to']
        #~ mail["From"] = self.configFile['mail']['from']
        #~ mail["Date"] = self.formatHTTPDate(datetime.utcnow())

    mail = MIMEMultipart()
    mail["To"] = responsible
    mail["From"] = fromaddr
    mail["Date"] = format_date_time(timegm(datetime.utcnow().utctimetuple()))

    warnlist = sorted(warnlist, key=lambda x: x[-1])
    next_expiry = warnlist[0][-1]

    mail["Subject"] = "In {!s}, the next certificate will expire".format(next_expiry)

    text = """Dear administrator,

The following certificates are about to expire:
"""

    for nth, (filename, cert, fingerprint, ttl) in enumerate(warnlist):
        text += """
{nth:2d}. {filename}
    SHA1: {fingerprint}
    Remaining time: {ttl}
""".format(
                                nth=nth+1,
                                filename=os.path.basename(filename),
                                fingerprint=
                                    format_fingerprint(fingerprint),
                                ttl=ttl)

    text += """
sincerely yours,
    certwatch.py"""

    mime_text = MIMEText(text)
    mime_text.set_charset("utf-8")
    mail.attach(mime_text)

    return mail

if __name__ == "__main__":
    import argparse
    import configparser

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c", "--config",
        default="/etc/certwatch.conf",
        help="Config file to use [defaults to /etc/certwatch.conf]"
    )

    args = parser.parse_args()

    args.config = open(args.config, "r")

    conf_parser = configparser.ConfigParser()

    conf_parser["DEFAULT"] = {
        "responsible": "root@localhost",
        "warn": "4 weeks"
    }

    conf_parser.read_file(args.config)

    warnings = {}

    for section in conf_parser.sections():
        filename = os.path.expanduser(section)
        cert, fingerprint = parse_certificate(filename)
        ttl = get_ttl(extract_validity(cert))

        warn_ttl = conf_parser.get(section, "warn")
        if warn_ttl.strip() != "never":
            warn_ttl = parse_config_timedelta(warn_ttl)
            if warn_ttl >= ttl:
                responsible = conf_parser.get(section, "responsible")
                warnings.setdefault(responsible, []).append(
                    (filename, cert, fingerprint, ttl)
                )

    for responsible, warnlist in warnings.items():
        mail = construct_warning_mail(
            responsible,
            warnlist,
            conf_parser.get("DEFAULT", "from")
        )
        print(mail.as_string())
