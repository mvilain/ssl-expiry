#!/usr/bin/env python3
#
# I chose this code because it didn't use a non-standard library, just urllib
# https://stackoverflow.com/questions/44280747/how-to-check-a-ssl-certificate-expiration-date-with-aiohttp
# shell https://www.shellhacks.com/openssl-check-ssl-certificate-expiration-date/
#
# I could have built on this code but it required pyopenssl, cryptography and idna which isn't always present
# https://gist.github.com/gdamjan/55a8b9eec6cf7b771f92021d93b87b2c
# code modified by Michael Vilain <michael@vilain.com>

import argparse
import datetime
import calendar
import json
import os
import pprint
import sys
import time
from urllib.request import ssl, socket

def conv_ssl_date(ssl_time):
    """
    :param ssl_time:
        format "mmm dd HH:MM:SS YYYY GMT" (dd is either a space + a number or 2 digits)
    :return:
        int of Unix epoch time correctly interpeting the timezone
    """
    ssl_format = '%b %d %H:%M:%S %Y %z'
    # this works but it's a pain
    #ssl_time_fixed = ssl_time[0:21] + "+0000"   # replace GMT with TZ offset
    ssl_time_fixed = ssl_time.replace("GMT", "+0000")
    utc_epoch = calendar.timegm(time.strptime(ssl_time_fixed, ssl_format))
    return utc_epoch

def dump_ssl(hostname, port):
    """
    :param:
        hostname -- fqdn of host to attempt gather SSL info on
        port -- int of port number to use to open the connection

    :returns:
        the following JSON object
    {
      "subject": [
        [[ "commonName", "example.com" ]],
        [[ "businessCategory", "Private Organization]" ]]
        [[ "countryName", "whatever" ]]
        [[ "stateOrProvinceName", "whatever" ]]
        [[ "Error", "why routine errored " ]]
      ],
      "issuer": [
        [[ "countryName", "US" ]],
        [[ "organizationName", "some-certificate-issuer" ]],
        [[ "commonName", "some-certificate-issuer-synonym" ]]
      ],
      "version": 3,
      "serialNumber": "000000000000000000000000000000000000",
      "notBefore": "mmm dd HH:MM:SS yyyy TZ",
      "notAfter": "mmm dd HH:MM:SS yyyy TZ",
      "subjectAltName": [
        [ "DNS", "example.com" ],
        [ "DNS", "www.example.com" ],
        [ "DNS", "subdomain2.example.com" ]
      ],
      "OCSP": [ "http://ocsp.int-x3.letsencrypt.org" ],
      "caIssuers": [ "http://cert.int-x3.letsencrypt.org/" ]
    }
    """
    context = ssl.create_default_context()
    # catch error if socket.create_connection will fail if hostname and port don't exist
    try:
        # this code is needed to allow be able to trap the error for non-existant domains
        # Identity: badssl-fallback-unknown-subdomain-or-no-sni"
        # https://en.wikipedia.org/wiki/Server_Name_Indication
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # print(ssock.version()) # TLS version
                # print(ssock.getpeercert())
                return json.dumps(ssock.getpeercert())
    except socket.gaierror:
        socket_gaierror_str = '{ "subject": [ "Error", "' + \
                              "Error8: nodename nor servname provided {}:{}, or not known".format(hostname, str(port)) + \
                              '" ] }'
        return socket_gaierror_str
    except:  # something else happened
        unk_error_str = '{ "subject": [ "Error", "' + \
                        "unknown error calling socket.create_connection for {}:{}".format(hostname, str(port)) + \
                        '" ] }'
        return unk_error_str

def log_output(url_list, dest):
    return

def sort_url_notAfterEpoch(url_dict):
    """
    extract the key from the url_dict object. used as a sort key for the list.sort function

    :param url_dict: a url_dict object with the following keys:
        "subject": a list of attributes like CommonName, BusinessCategory, CountryName, StateOrProvince
        "issuer": a list of attributes like CountryName, OrganizationName, CommonName
        "version": int--version of the SSL certificate (usually 3)
        "serialNumber": a unique hash string for the SSL serial#
        "notBefore": "mmm dd HH:MM:SS yyyy GMT"
        "notAfter": "mmm dd HH:MM:SS yyyy GMT"
        "subjectAltName": a list of 2-element lists of alternate DNS names valid for this certificate
        "OCSP": the Online Certificate Status Protocol server that validated this certificate
        "caIssuers": the Certificate Authority that issued the root certificate for the SSL chain
        "notBeforeEpoch": int--the UNIX epoch timestamp for start of "this SSL is valid" state
        "notAfterEpoch": int--the UNIX epoch timestamp for end of "this SSL is valid" state
        "base_url": the string used to obtain the SSL certificate information
        "base_port": int-port used to obtain the SSL certificate information

    valid return keys (because they must be a single value)
        one of the following:
            base_url_notBeforeEpoch
            base_url_notAfterEpoch
            base_url

    :return:
        returns the value for the key requested
        (no need to check the key parameter as the function will be called internally by a jacket function)
    """
    return url_dict["base_url_notAfterEpoch"]
def sort_url_notBeforeEpoch(url_dict):
    """
    extract the key from the url_dict object. used as a sort key for the list.sort function

    :param url_dict: a url_dict object with the following keys:
        "subject": a list of attributes like CommonName, BusinessCategory, CountryName, StateOrProvince
        "issuer": a list of attributes like CountryName, OrganizationName, CommonName
        "version": int--version of the SSL certificate (usually 3)
        "serialNumber": a unique hash string for the SSL serial#
        "notBefore": "mmm dd HH:MM:SS yyyy GMT"
        "notAfter": "mmm dd HH:MM:SS yyyy GMT"
        "subjectAltName": a list of 2-element lists of alternate DNS names valid for this certificate
        "OCSP": the Online Certificate Status Protocol server that validated this certificate
        "caIssuers": the Certificate Authority that issued the root certificate for the SSL chain
        "base_url_notBeforeEpoch": int--the UNIX epoch timestamp for start of "this SSL is valid" state
        "base_url_notAfterEpoch": int--the UNIX epoch timestamp for end of "this SSL is valid" state
        "base_url": the string used to obtain the SSL certificate information
        "base_port": int-port used to obtain the SSL certificate information

    :return:
        returns the value for the key requested
        (no need to check the key parameter as the function will be called internally by a jacket function)
    """
    return url_dict["base_url_notBeforeEpoch"]
def sort_url_base_url(url_dict):
    """
    extract the key from the url_dict object. used as a sort key for the list.sort function

    :param url_dict: a url_dict object with the following keys:
        "subject": a list of attributes like CommonName, BusinessCategory, CountryName, StateOrProvince
        "issuer": a list of attributes like CountryName, OrganizationName, CommonName
        "version": int--version of the SSL certificate (usually 3)
        "serialNumber": a unique hash string for the SSL serial#
        "notBefore": "mmm dd HH:MM:SS yyyy GMT"
        "notAfter": "mmm dd HH:MM:SS yyyy GMT"
        "subjectAltName": a list of 2-element lists of alternate DNS names valid for this certificate
        "OCSP": the Online Certificate Status Protocol server that validated this certificate
        "caIssuers": the Certificate Authority that issued the root certificate for the SSL chain
        "base_url_notBeforeEpoch": int--the UNIX epoch timestamp for start of "this SSL is valid" state
        "base_url_notAfterEpoch": int--the UNIX epoch timestamp for end of "this SSL is valid" state
        "base_url": the string used to obtain the SSL certificate information
        "base_port": int-port used to obtain the SSL certificate information

    valid return keys (because they must be a single value)
        one of the following:
            base_url_notBeforeEpoch
            base_url_notAfterEpoch
            base_url

    :return:
        returns the value for the key requested
        (no need to check the key parameter as the function will be called internally by a jacket function)
    """
    return url_dict["base_url"]

# ------------------------------------------------------------------------#
# parse arguments
# ------------------------------------------------------------------------#
parser = argparse.ArgumentParser(
    description="""
    scan a list of fully qualified domain names from a file, extracts the SSL Server\ 
    Certificate security details (if any), and displays the certificate info\
    """)
# file = list of strings or 'None'
parser.add_argument('-f', '--file', nargs=1, required=True,
                    help='input file of FQDN to scan, 1 line per host')
# output = string with argument name or 'None'
parser.add_argument('-o', '--output', nargs=1,
                    help='outputs FQDN SSL info to FILE')
parser.add_argument('-s', '--sort', action='store_true',
                    help='prints the FQDN info in descending order of expiration date')
parser.add_argument('-v', '--verbose', action='store_true',
                    help='prints the ALL the information from the SSL certificate')
args = parser.parse_args()
FILE = os.path.basename(sys.argv[0])
#print(args,FILE)

# loop thru list of file strings
try:
    file_lines = open(args.file[0], 'r')    # a list with 1 element
except FileNotFoundError:
    print("{}: [Errno 2] No such file or directory: {}".format(FILE, args.file[0]))
    exit(1)
except:
    print("{}: can't open file {}".format(FILE,args.file[0]))
    exit(2)

# done with all file processing, now do the output depending on the options passed
if args.output:
    # catch possible error if can't write output file
    try:
        output_lines = open(args.output[0], 'w') # a list with 1 element
        pp_out = pprint.PrettyPrinter(indent=2, stream=output_lines)
    except PermissionError:
        print("{}: [Errno 13] Permission denied: '{}'".format(FILE,args.output[0]))
        pp_out = pprint.PrettyPrinter(indent=2)
    except:
        print("{}: can't open {} for writing".format(FILE,args.output[0]))
        # rather than quiting with output, output to st.out
        pp_out = pprint.PrettyPrinter(indent=2)
else:
    pp_out = pprint.PrettyPrinter(indent=2)

# calculate some dates for use in testing expired or not valid cert dates
notAfterNow = datetime.datetime.utcnow() - datetime.timedelta(days=30) # expired 30 days ago
notAfterNowEpoch = int(time.mktime(notAfterNow.timetuple()))
notBeforeNow = datetime.datetime.utcnow() + datetime.timedelta(days=30) # not valid until 30 days from now
notBeforeNowEpoch = int(time.mktime(notBeforeNow.timetuple()))
Now = datetime.datetime.utcnow()
NowEpoch = int(time.mktime(Now.timetuple()))
#print(Now, NowEpoch, notAfterNow, notAfterNowEpoch,notBeforeNow, notBeforeNowEpoch)
urls = []       # create a list of URL JSON dictionaries

# loop thru lines instead reading them all into a list with readlines()
for line in file_lines:
    if line[0] == "#":  # ignore comment lines
        continue
    elif line[0] == "\n":   # ignore blank lines
        continue
    else:
        # assumes each line is a fqdn, not a URL; catch this error?
        base_url = line[0:len(line) - 1]  # trim trailing "\n"

        base_url_json = dump_ssl(base_url, 443)
        # OCSP comes before other fields when dictionary is sorted, so replace it with lowercase
        # and load json dump into a python dict object
        base_url_dict = json.loads(base_url_json.replace("OCSP","ocsp"))
        base_url_dict["base_url"] = base_url
        base_url_dict["base_url_port"] = 443
        base_url_dict["base_url_json"] = base_url_json  # saving this for full listing

        # subject key contains at least a 2-element list of strings
        if "Error" in base_url_dict["subject"]:
            base_url_dict["base_url_notAfterEpoch"] = notAfterNowEpoch  # expired 30 days ago
            base_url_dict["base_url_notBeforeEpoch"] = notBeforeNowEpoch # not valid until this date
            base_url_dict["base_url_status"] = "{} EXPIRED ({})".format(base_url, notAfterNow)
        else:
            base_url_dict["base_url_notAfterEpoch"] = conv_ssl_date(base_url_dict["notAfter"])
            base_url_dict["base_url_notBeforeEpoch"] = conv_ssl_date(base_url_dict["notBefore"])
            if base_url_dict["base_url_notAfterEpoch"] < notAfterNowEpoch:
                base_url_dict["base_url_status"] = "{} EXPIRED ({})".format(base_url, notAfter)
            else:
                base_url_dict["base_url_status"] = "{} OK ({})".format(base_url, base_url_dict["notAfter"])
            # for non-verbose printing, remove various extraneous keys
            if not args.verbose:
                # use pop instead of del because then I don't need to use a try/except block
                # and I don't know if a continue in the except block will skip to the next entry
                result = base_url_dict.pop("caIssuers", None)
                result = base_url_dict.pop("crlDistributionPoints", None)
                result = base_url_dict.pop("ocsp", None)
                result = base_url_dict.pop("serialNumber", None)
                result = base_url_dict.pop("version", None)

        urls.append(base_url_dict)

# done with all file processing, now do the output depending on the options passed
if args.sort:
    pp_out.pprint(sorted(urls,key=sort_url_notAfterEpoch))
else:
    pp_out.pprint(sorted(urls,key=sort_url_base_url))


# todo:
# add summary report at the end
# add a brief mode that displays minimal info
# quiet option would not print any message if --output specified, ignored if --output not specified
