#!/usr/bin/python3
import re
import os
import sys
import hashlib
import smtplib
import logging
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

CONFIG_TIMEDELTA_RE = re.compile(r"([0-9]+(\.[0-9]*)?)\s*([a-zA-Z]+)")

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

def get_ttl(not_after):
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

def construct_warning_mail(responsible, warnlist, fromaddr, subjectfmt):
    mail = MIMEMultipart()
    mail["To"] = responsible
    mail["From"] = fromaddr
    mail["Date"] = format_date_time(timegm(datetime.utcnow().utctimetuple()))

    warnlist = sorted(warnlist, key=lambda x: x[-1])
    next_expiry = warnlist[0][-1]

    mail["Subject"] = subjectfmt.format(
        timedelta=str(next_expiry),
        next_expiry=str(datetime.utcnow()+next_expiry),
        warn_count=len(warnlist))

    text = """Dear administrator,

The following certificates are about to expire:
"""

    for nth, (filename, cert, fingerprint, not_after, ttl) in enumerate(warnlist):
        text += """
{nth:2d}. {filename}
    SHA1: {fingerprint}
    Remaining time: {ttl}
    Expiry at: {expiry}
""".format(
                                nth=nth+1,
                                filename=os.path.basename(filename),
                                fingerprint=
                                    format_fingerprint(fingerprint),
                                ttl=ttl,
                                expiry=not_after)

    text += """
sincerely yours,
    certwatch.py"""

    mime_text = MIMEText(text)
    mime_text.set_charset("utf-8")
    mail.attach(mime_text)

    return mail

def log_error(msg_base, exc, logging=logging):
    if not hasattr(exc, "smtp_error"):
        logging.error("%s: %s", msg_base, exc)
    else:
        try:
            logging.error("%s: %s", msg_base, exc.smtp_error.decode())
        except UnicodeDecodeError as err:
            logging.error("%s: (decode of error message failed) %s", msg_base, exc.smtp_error)

def log_smtp_error(exc, logging=logging):
    log_error("Could not connect to SMTP",
              exc,
              logging=logging)

def log_send_error(exc, logging=logging):
    log_error("While sending mail",
              exc,
              logging=logging)


if __name__ == "__main__":
    import argparse
    import configparser

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-c", "--config",
        default="/etc/certwatch.conf",
        help="Config file to use [defaults to /etc/certwatch.conf]"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="count",
        default=0,
        help="Increase verbosity level"
    )

    args = parser.parse_args()

    LEVEL_MAP = {
        0: 'ERROR',
        1: 'WARNING',
        2: 'INFO',
        3: 'DEBUG'
    }

    logging.basicConfig(format='{}: [%(levelname)s] %(message)s'.format(os.path.basename(sys.argv[0])),
                        level=LEVEL_MAP.get(args.verbose, 'DEBUG'))


    args.config = open(args.config, "r")

    conf_parser = configparser.ConfigParser()

    conf_parser["DEFAULT"] = {
        "responsible": "root@localhost",
        "warn": "4 weeks"
    }

    conf_parser.read_file(args.config)

    warnings = {}

    certpath = conf_parser.get("DEFAULT", "certdir", fallback="/")
    subjectfmt = conf_parser.get(
        "DEFAULT", "subject",
        fallback="In {timedelta}, the next certificate will expire")

    for section in conf_parser.sections():
        filename = os.path.join(certpath, os.path.expanduser(section))
        logging.debug("reading: %s", filename)
        try:
            cert, fingerprint = parse_certificate(filename)
        except FileNotFoundError as err:
            logging.error(str(err))
            continue
        _, not_after = extract_validity(cert)
        ttl = get_ttl(not_after)
        logging.info("cert %s expires in %s",
                     filename, ttl)

        warn_ttl = conf_parser.get(section, "warn")
        if warn_ttl.strip() != "never":
            try:
                warn_ttl = parse_config_timedelta(warn_ttl)
            except ValueError:
                logging.error("config error: could not parse time delta: %s", warn_ttl)
                continue
            if warn_ttl >= ttl:
                responsible = conf_parser.get(section, "responsible")
                logging.debug("cert %s is below warning threshold, "
                              "notifying %s",
                              filename,
                              responsible)
                warnings.setdefault(responsible, []).append(
                    (filename, cert, fingerprint, not_after, ttl)
                )



    smtp_host = conf_parser.get("DEFAULT", "smtp_host", fallback="localhost")
    if not smtp_host.strip():
        logging.error("Invalid smtp host name: {!r}".format(smtp_host))
        sys.exit(1)
    smtp_port = conf_parser.getint("DEFAULT", "smtp_port", fallback=0)
    try:
        if conf_parser.getboolean("DEFAULT", "smtp_ssl", fallback=False):
            smtp = smtplib.SMTP_SSL(smtp_host, smtp_port)
        else:
            smtp = smtplib.SMTP(smtp_host, smtp_port)
            if conf_parser.getboolean("DEFAULT", "smtp_starttls", fallback=True):
                smtp.starttls()
        if conf_parser.has_option("DEFAULT", "smtp_helo"):
            helo = conf_parser["DEFAULT"]["smtp_helo"]
            try:
                smtp.ehlo(helo)
            except:
                smtp.helo(helo)
    except ConnectionError as err:
        log_smtp_error(err)
        sys.exit(1)
    except TimeoutError as err:
        log_smtp_error(err)
        sys.exit(1)
    except smtplib.SMTPException as err:
        log_smtp_error(err)
        sys.exit(1)
    except Exception as err:
        logging.error("while connecting to smtp server:")
        logging.exception(err)
        sys.exit(1)

    try:
        if conf_parser.has_option("DEFAULT", "smtp_user"):
            smtp.login(conf_parser["DEFAULT"]["smtp_user"], conf_parser.get("DEFAULT", "smtp_password", fallback=""))
    except smtplib.SMTPAuthenticationError as err:
        log_smtp_error(err)
        sys.exit(1)

    mail_from = conf_parser.get("DEFAULT", "from")

    for responsible, warnlist in warnings.items():
        mail = construct_warning_mail(
            responsible,
            warnlist,
            mail_from,
            subjectfmt
        )

        logging.debug("sending mail: to=<%s>, from=<%s>, \n%s",
                      responsible,
                      mail_from,
                      mail)
        try:
            smtp.sendmail(mail_from, responsible, mail.as_string())
        except smtplib.SMTPException as err:
            log_send_error(err)
            continue
        except TimeoutError as err:
            log_send_error(err)
            sys.exit(1)
        except ConnectionError as err:
            log_send_error(err)
            sys.exit(1)
        except Exception as err:
            log_send_error(err)
            sys.exit(1)

    smtp.quit()
