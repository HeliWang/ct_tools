# Copyright (c) 2014, NORDUnet A/S.
# See LICENSE for licensing information.

import subprocess
import json
import base64
import urllib
import urllib2
import ssl
import urlparse
import struct
import sys
import hashlib
#import ecdsa
import datetime
import cStringIO
import zipfile
import shutil
from copy import deepcopy
from certkeys import publickeys

#from Crypto.Hash import SHA256
#import Crypto.PublicKey.RSA as RSA
#from Crypto.Signature import PKCS1_v1_5


def prompt_confirm(msg = "", default = True):
    print msg

    while True:
        if default:
            print "Are you sure? (Y/n)"
        else:
            print "Are you sure? (y/N)"
        
        import sys
        data = sys.stdin.readline()
        
        if data == "y\n":
            return True
        elif data == "n\n":
            return False
        elif data == "\n":
            return default
        else:
            print "Answer either y or n"

def time_str(ts = None):
    if ts is None:
        return datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    else:
        return datetime.datetime.fromtimestamp(ts / 1000, UTC()).strftime("%Y-%m-%d %H:%M:%S")

def compare_lists(new, old):
    added_items  = []
    removed_items  = []

    for item in new:
        if not item in old:
            added_items.append(item)

    for item in old:
        if not item in new:
            removed_items.append(item)
    return added_items, removed_items

def get_all_roots(base_url):
    result = urlopen(base_url + "ct/v1/get-roots").read()
    certs = json.loads(result)["certificates"]
    # print time.strftime('%H:%M:%S') + " Received " + str(len(certs)) + " certs from " + base_url

    for accepted_cert in certs:
        subject = get_cert_info(base64.decodestring(accepted_cert))["subject"]
        issuer = get_cert_info(base64.decodestring(accepted_cert))["issuer"]
        if subject == issuer:
            root_cert = base64.decodestring(accepted_cert)
    return certs

def verify_inclusion_by_hash(base_url, leaf_hash):
    try: 
        tmp_sth = get_sth(base_url)
        proof = get_proof_by_hash(base_url, leaf_hash, tmp_sth["tree_size"])

        decoded_inclusion_proof = []
        for item in proof["audit_path"]:
            decoded_inclusion_proof.append(base64.b64decode(item))
        
        root = base64.b64encode(verify_inclusion_proof(decoded_inclusion_proof, proof["leaf_index"], tmp_sth["tree_size"], leaf_hash))

        if tmp_sth["sha256_root_hash"] == root:
            return True
        else:
            # print time.strftime('%H:%M:%S') + " ERROR: Could not prove inclusion for entry " + str(proof["leaf_index"]) + " in " + base_url
            return False
    except:
        # print time.strftime('%H:%M:%S') + " ERROR: Could not prove inclusion for hashed entry in " + base_url
        return False

def check_domain(raw_entry, log=None):
    orig_entry = extract_original_entry(raw_entry)
    try:
        cert_info = my_get_cert_info(orig_entry[0][0])
        if log:
            cert_info["log"] = log[8:-1] # strip generic URL stuff
        return cert_info
    except IndexError:
        return None

def check_domain_extended(raw_entry, log=None):
    orig_entry = extract_original_entry(raw_entry)
    # try:
    cert_info = my_get_more_cert_info(orig_entry[0][0])
    # except:
    #     print "Error in my_get_more_cert_info"
    #     return None
    try:
        # print len(orig_entry[0])
        cert_info["chain_length"] = str(len(orig_entry[0]))
        cert_info["validation"] = get_validation_type(cert_info["policy"])
        cert_info["in_mozilla"] = validate_cert(orig_entry[0][-1])
        # print my_get_all_cert_info(orig_entry[0][-1])
        if log:
            cert_info["log"] = log[8:-1] # strip generic URL stuff
        return cert_info
    except IndexError:
        print "Error while setting additional parameters"
        return None

def check_domain_all(raw_entry, log=None):
    orig_entry = extract_original_entry(raw_entry)
    try:
        cert_info = my_get_all_cert_info(orig_entry[0][0])
        if log:
            cert_info["log"] = log[8:-1] # strip generic URL stuff
        return cert_info
    except IndexError:
        return None

def get_full_cert(entry):
    try:
        log = "https://" + entry["log"] + "/"
        leaf_hash = entry["leaf_hash"]
    except:
        print "Could not get stats from entry."
        return
    # Get tree size in sth
    sth = get_sth(log)
    # Get index (rest of proof discarded)
    proof = get_proof_by_hash(log, base64.b64decode(leaf_hash), sth["tree_size"])
    leaf_index = proof["leaf_index"]
    # Get full entry
    raw_entry = get_entries(log, leaf_index, leaf_index)["entries"][0]
    cert = check_domain_all(raw_entry)
    entry["index"] = leaf_index
    return cert

def encode_tree(tree):
    res = []
    for layer in tree:
        res.append([])
        for item in layer:
            tmp = base64.b64encode(item)
            res[-1].append(tmp)
    return res

def decode_tree(tree):
    res = []
    for layer in tree:
        res.append([])
        for item in layer:
            tmp = base64.b64decode(item)
            res[-1].append(tmp)
    return res

def append_file(fn, content):
    with open(fn, 'a') as f:
        for item in content:
            try: 
                f.write(json.dumps(item) + "\n")
            except:
                pass

def validate_cert(s):
    p = subprocess.Popen(
        ["openssl", "x509", "-inform", "DER"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    converted = p.communicate(s)
    # print converted
    p = subprocess.Popen(
        ["openssl", "verify", "-x509_strict", "-CAfile", "certdata.txt"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    parsed = p.communicate(converted[0])
    # print parsed
    res = parsed[0][7:-1]
    if res == "OK":
        return "OK"
    else:
        try:
            return res.split("\n")[-2]
        except:
            print parsed

def get_cert_info(s):
    p = subprocess.Popen(
        ["openssl", "x509", "-noout", "-subject", "-issuer", "-inform", "der"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    parsed = p.communicate(s)
    if parsed[1]:
        print "ERROR:", parsed[1]
        # sys.exit(1)
        raise Exception
    result = {}
    for line in parsed[0].split("\n"):
        (key, sep, value) = line.partition("=")
        if sep == "=":
            result[key] = value
    return result

def my_get_cert_info(s):
    p = subprocess.Popen(
        ["openssl", "x509", "-fingerprint", "-text", "-noout", "-inform", "der"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    parsed = p.communicate(s)
    if parsed[1]:
        print "ERROR:", parsed[1]
        # sys.exit(1)
        raise Exception
    result = {}
    prev = ""
    for line in parsed[0].split("\n"):
        if "Subject:" in line:
            result["subject"] = line.split("Subject: ")[1]
        if "Issuer:" in line:
            try:
                result["issuer"] = line.split("Issuer: ")[1]
            except:
                print line
                sys.exit()
        if "Subject Alternative Name" in prev:
            result["SAN"] = line.lstrip()
        if "Not After" in line:
            result["not_after"] = line.split(": ")[1]
        if "Not Before" in line:
            result["not_before"] = line.split(": ")[1]
        prev = line
    return result

def my_get_more_cert_info(s):
    p = subprocess.Popen(
        ["openssl", "x509", "-fingerprint", "-text", "-noout", "-inform", "der"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    parsed = p.communicate(s)
    if parsed[1]:
        print "ERROR:", parsed[1]
        # sys.exit(1)
        raise Exception
    result = {}
    result["policy"] = []
    result["keylength"] = "N/A" # Default value
    prev = ""
    for line in parsed[0].split("\n"):
        if "Subject:" in line:
            result["subject"] = line.split("Subject: ")[1]
        if "        Issuer:" in line:
            try:
                result["issuer"] = line.split("Issuer: ")[1]
            except:
                print line
                sys.exit()
        if "Public-Key:" in line:
            result["keylength"] = line.split(':')[1][2:-5]
        if "Signature Algorithm:" in line:
            result["sig_algorithm"] = line.split("Signature Algorithm: ")[1]
        if "Public Key Algorithm:" in line:
            result["pubkey_algorithm"] = line.split("Public Key Algorithm: ")[1]
        if "Subject Alternative Name" in prev:
            result["SAN"] = line.lstrip()
        if "Serial Number:" in prev:
            if prev.split("Serial Number:")[1] == "":
                # print prev, prev.split("Serial Number:")
                result["serial"] = line.lstrip()
            else:
                # print prev, prev.split("Serial Number:")
                result["serial"] = prev.split("Serial Number: ")[1]
        if "Not After" in line:
            result["not_after"] = line.split(": ")[1]
        if "Not Before" in line:
            result["not_before"] = line.split(": ")[1]
        if "Policy:" in line:
            result["policy"].append(line.split("Policy: ")[1])
        prev = line
    return result

def get_validation_type(policy_list):
    DV_list = ["2.23.140.1.2.1"]
    OV_list = ["2.23.140.1.2.2"]
    EV_list = [
    "1.3.159.1.17.1",
    "1.3.6.1.4.1.34697.2.1",
    "1.3.6.1.4.1.34697.2.2",
    "1.3.6.1.4.1.34697.2.3",
    "1.3.6.1.4.1.34697.2.4",
    "1.2.40.0.17.1.22",
    "2.16.578.1.26.1.3.3",
    "1.3.6.1.4.1.17326.10.14.2.1.2",
    "1.3.6.1.4.1.17326.10.8.12.1.2",
    "1.3.6.1.4.1.6449.1.2.1.5.1",
    "2.16.840.1.114412.2.1",
    "2.16.840.1.114412.1.3.0.2",
    "2.16.528.1.1001.1.1.1.12.6.1.1.1",
    "2.16.792.3.0.4.1.1.4",
    "2.16.840.1.114028.10.1.2",
    "0.4.0.2042.1.4",
    "0.4.0.2042.1.5",
    "1.3.6.1.4.1.13177.10.1.3.10",
    "1.3.6.1.4.1.14370.1.6",
    "1.3.6.1.4.1.4146.1.1",
    "2.16.840.1.114413.1.7.23.3",
    "1.3.6.1.4.1.14777.6.1.1",
    "2.16.792.1.2.1.1.5.7.1.9",
    "1.3.6.1.4.1.22234.2.5.2.3.1",
    "1.3.6.1.4.1.782.1.2.1.8.1",
    "1.3.6.1.4.1.8024.0.2.100.1.2",
    "1.2.392.200091.100.721.1",
    "2.16.840.1.114414.1.7.23.3",
    "1.3.6.1.4.1.23223.2",
    "1.3.6.1.4.1.23223.1.1.1",
    "2.16.756.1.83.21.0",
    "2.16.756.1.89.1.2.1.1",
    "2.16.840.1.113733.1.7.48.1",
    "2.16.840.1.114404.1.1.2.4.1",
    "2.16.840.1.113733.1.7.23.6",
    "1.3.6.1.4.1.6334.1.100.1",
    "2.16.840.1.114171.500.9",
    "1.3.6.1.4.1.36305.2"
]

    status = "DV"

    for policy in policy_list:
        if policy in EV_list:
            status = "EV"
        if policy in OV_list:
            status = "OV"
        if policy in DV_list:
            status = "DV"
    return status


def my_get_all_cert_info(s):
    p = subprocess.Popen(
        ["openssl", "x509", "-fingerprint", "-text", "-noout", "-inform", "der"],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)
    parsed = p.communicate(s)
    if parsed[1]:
        print "ERROR:", parsed[1]
        # sys.exit(1)
        raise Exception
    return parsed[0]


def get_pemlike(filename, marker):
    return get_pemlike_from_file(open(filename), marker)

def get_pemlike_from_file(f, marker):
    entries = []
    entry = ""
    inentry = False

    for line in f:
        line = line.strip()
        if line == "-----BEGIN " + marker + "-----":
            entry = ""
            inentry = True
        elif line == "-----END " + marker + "-----":
            entries.append(base64.decodestring(entry))
            inentry = False
        elif inentry:
            entry += line
    return entries

def get_certs_from_file(certfile):
    return get_pemlike(certfile, "CERTIFICATE")

def get_certs_from_string(s):
    f = cStringIO.StringIO(s)
    return get_pemlike_from_file(f, "CERTIFICATE")

def get_precerts_from_string(s):
    f = cStringIO.StringIO(s)
    return get_pemlike_from_file(f, "PRECERTIFICATE")

def get_eckey_from_file(keyfile):
    keys = get_pemlike(keyfile, "EC PRIVATE KEY")
    assert len(keys) == 1
    return keys[0]

def get_public_key_from_file(keyfile):
    keys = get_pemlike(keyfile, "PUBLIC KEY")
    assert len(keys) == 1
    return keys[0]

def get_root_cert(issuer):
    accepted_certs = \
        json.loads(open("googlelog-accepted-certs.txt").read())["certificates"]

    root_cert = None

    for accepted_cert in accepted_certs:
        subject = get_cert_info(base64.decodestring(accepted_cert))["subject"]
        if subject == issuer:
            root_cert = base64.decodestring(accepted_cert)

    return root_cert

class sslparameters:
    sslcontext = None

def create_ssl_context(cafile=None):
    try:
        sslparameters.sslcontext = ssl.create_default_context(cafile=cafile)
    except AttributeError:
        sslparameters.sslcontext = None

def get_opener():
    try:
        opener = urllib2.build_opener(urllib2.HTTPSHandler(context=sslparameters.sslcontext))
    except TypeError:
        opener = urllib2.build_opener(urllib2.HTTPSHandler())
    return opener

def urlopen(url, data=None):
    return get_opener().open(url, data)

def pyopenssl_https_get(url):
    """
    HTTPS GET-function to use when running old Python < 2.7
    """
    from OpenSSL import SSL
    import socket

    # TLSv1 is the best we can get on Python 2.6
    context = SSL.Context(SSL.TLSv1_METHOD)
    sock = SSL.Connection(context, socket.socket(socket.AF_INET, socket.SOCK_STREAM))

    url_without_scheme = url.split('https://')[-1]
    host = url_without_scheme.split('/')[0]
    path = url_without_scheme.split('/', 1)[1]
    http_get_request = ("GET /{path} HTTP/1.1\r\n"
                        "Host: {host}\r\n"
                        "\r\n"
                        ).format(path=path, host=host)

    sock.connect((host, 443))
    sock.write(http_get_request)
    response = sock.recv(1024)
    response_lines = response.rsplit('\n')

    # We are only interested in the actual response,
    # without headers, contained in the last line.
    return response_lines[len(response_lines) - 1]

def get_sth(baseurl):
    result = urlopen(baseurl + "ct/v1/get-sth").read()
    return json.loads(result)

def get_sth_and_ip(baseurl):
    data = urlopen(baseurl + "ct/v1/get-sth")
    ip = data.fp._sock.fp._sock.getpeername()[0]
    result = data.read()
    return json.loads(result), ip

def get_proof_by_hash(baseurl, hash, tree_size):
    # try:
        params = urllib.urlencode({"hash":base64.b64encode(hash),
                                   "tree_size":tree_size})
        result = \
          urlopen(baseurl + "ct/v1/get-proof-by-hash?" + params).read()
        return json.loads(result)
    # except urllib2.HTTPError, e:
    #     print "ERROR:", e.read()
        # sys.exit(1)
        # raise Exception

def get_consistency_proof(baseurl, tree_size1, tree_size2):
    # try:
        params = urllib.urlencode({"first":tree_size1,
                                   "second":tree_size2})
        result = \
          urlopen(baseurl + "ct/v1/get-sth-consistency?" + params).read()
        return json.loads(result)["consistency"]
    # except urllib2.HTTPError, e:
    #     print "ERROR:", e.read()
        # sys.exit(1)

def tls_array(data, length_len):
    length_bytes = struct.pack(">Q", len(data))[-length_len:]
    return length_bytes + data

def unpack_tls_array(packed_data, length_len):
    padded_length = ["\x00"] * 8
    padded_length[-length_len:] = packed_data[:length_len]
    (length,) = struct.unpack(">Q", "".join(padded_length))
    unpacked_data = packed_data[length_len:length_len+length]
    assert len(unpacked_data) == length, \
      "data is only %d bytes long, but length is %d bytes" % \
      (len(unpacked_data), length)
    rest_data = packed_data[length_len+length:]
    return (unpacked_data, rest_data)

def add_chain(baseurl, submission):
    try:
        result = urlopen(baseurl + "ct/v1/add-chain", json.dumps(submission)).read()
        return json.loads(result)
    except urllib2.HTTPError, e:
        return "ERROR " + str(e.code) + " : " + e.read()
        # if e.code == 400:
        return None
        # sys.exit(1)
    except ValueError, e:
        print "==== FAILED REQUEST ===="
        print submission
        print "======= RESPONSE ======="
        print result
        print "========================"
        raise e

def add_prechain(baseurl, submission):
    try:
        result = urlopen(baseurl + "ct/v1/add-pre-chain",
            json.dumps(submission)).read()
        return json.loads(result)
    except urllib2.HTTPError, e:
        # print "ERROR", e.code,":", e.read()
        # if e.code == 400:
        return None
        # sys.exit(1)
    except ValueError, e:
        print "==== FAILED REQUEST ===="
        print submission
        print "======= RESPONSE ======="
        print result
        print "========================"
        raise e

def get_entries(baseurl, start, end):
    params = urllib.urlencode({"start":start, "end":end})
    # try:
    result = urlopen(baseurl + "ct/v1/get-entries?" + params).read()
    return json.loads(result)
    # except urllib2.HTTPError, e:
    #     print "ERROR:", e.read()
        # sys.exit(1)

def extract_precertificate(precert_chain_entry):
    (precert, certchain) = unpack_tls_array(precert_chain_entry, 3)
    return (precert, certchain)

def decode_certificate_chain(packed_certchain):
    (unpacked_certchain, rest) = unpack_tls_array(packed_certchain, 3)
    assert len(rest) == 0
    certs = []
    while len(unpacked_certchain):
        (cert, rest) = unpack_tls_array(unpacked_certchain, 3)
        certs.append(cert)
        unpacked_certchain = rest
    return certs

def decode_signature(signature):
    (hash_alg, signature_alg) = struct.unpack(">bb", signature[0:2])
    (unpacked_signature, rest) = unpack_tls_array(signature[2:], 2)
    assert rest == ""
    return (hash_alg, signature_alg, unpacked_signature)

def encode_signature(hash_alg, signature_alg, unpacked_signature):
    signature = struct.pack(">bb", hash_alg, signature_alg)
    signature += tls_array(unpacked_signature, 2)
    return signature

def check_signature(baseurl, signature, data, publickey=None):
    if publickey == None:
        if baseurl in publickeys:
            publickey = base64.decodestring(publickeys[baseurl])
        else:
            print >>sys.stderr, "Public key for", baseurl, \
                "not found, specify key file with --publickey"
            # sys.exit(1)
            raise Exception
    (hash_alg, signature_alg, unpacked_signature) = decode_signature(signature)
    assert hash_alg == 4, \
        "hash_alg is %d, expected 4" % (hash_alg,) # sha256
    assert (signature_alg == 3 or signature_alg == 1), \
        "signature_alg is %d, expected 1 or 3" % (signature_alg,) # ecdsa

    if signature_alg == 3:
        vk = ecdsa.VerifyingKey.from_der(publickey)
        vk.verify(unpacked_signature, data, hashfunc=hashlib.sha256,
              sigdecode=ecdsa.util.sigdecode_der)
    else:
        h = SHA256.new(data)
        # h = hashlib.sha256(data).digest()

        rsa_key = RSA.importKey(publickey)
        verifier = PKCS1_v1_5.new(rsa_key)
        # print "HASH: ",h
        # print "UNPACKED SIGNATURE: ",unpacked_signature
        assert verifier.verify(h, unpacked_signature), \
            "could not verify RSA signature"

def parse_auth_header(authheader):
    splittedheader = authheader.split(";")
    (signature, rawoptions) = (splittedheader[0], splittedheader[1:])
    options = dict([(e.partition("=")[0], e.partition("=")[2]) for e in rawoptions])
    return (base64.b64decode(signature), options)

def check_auth_header(authheader, expected_key, publickeydir, data, path):
    if expected_key == None:
        return True
    (signature, options) = parse_auth_header(authheader)
    keyname = options.get("key")
    if keyname != expected_key:
        raise Exception("Response claimed to come from %s, expected %s" % (keyname, expected_key))
    publickey = get_public_key_from_file(publickeydir + "/" + keyname + ".pem")
    vk = ecdsa.VerifyingKey.from_der(publickey)
    vk.verify(signature, "%s\0%s\0%s" % ("REPLY", path, data), hashfunc=hashlib.sha256,
              sigdecode=ecdsa.util.sigdecode_der)
    return True

def http_request(url, data=None, key=None, verifynode=None, publickeydir="."):
    opener = get_opener()

    (keyname, keyfile) = key
    privatekey = get_eckey_from_file(keyfile)
    sk = ecdsa.SigningKey.from_der(privatekey)
    parsed_url = urlparse.urlparse(url)
    if data == None:
        data_to_sign = parsed_url.query
        method = "GET"
    else:
        data_to_sign = data
        method = "POST"
    signature = sk.sign("%s\0%s\0%s" % (method, parsed_url.path, data_to_sign), hashfunc=hashlib.sha256,
                        sigencode=ecdsa.util.sigencode_der)
    opener.addheaders = [('X-Catlfish-Auth', base64.b64encode(signature) + ";key=" + keyname)]
    result = opener.open(url, data)
    authheader = result.info().get('X-Catlfish-Auth')
    data = result.read()
    check_auth_header(authheader, verifynode, publickeydir, data, parsed_url.path)
    return data

def get_signature(baseurl, data, key=None):
    try:
        params = json.dumps({"plop_version":1, "data": base64.b64encode(data)})
        result = http_request(baseurl + "plop/v1/signing/sth", params, key=key)
        parsed_result = json.loads(result)
        return base64.b64decode(parsed_result.get(u"result"))
    except urllib2.HTTPError, e:
        print "ERROR: get_signature", e.read()
        raise e

def create_signature(baseurl, data, key=None):
    unpacked_signature = get_signature(baseurl, data, key)
    return encode_signature(4, 3, unpacked_signature)

def check_sth_signature(baseurl, sth, publickey=None):
    signature = base64.decodestring(sth["tree_head_signature"])

    version = struct.pack(">b", 0)
    signature_type = struct.pack(">b", 1)
    timestamp = struct.pack(">Q", sth["timestamp"])
    tree_size = struct.pack(">Q", sth["tree_size"])
    hash = base64.decodestring(sth["sha256_root_hash"])
    tree_head = version + signature_type + timestamp + tree_size + hash

    check_signature(baseurl, signature, tree_head, publickey=publickey)

def create_sth_signature(tree_size, timestamp, root_hash, baseurl, key=None):
    version = struct.pack(">b", 0)
    signature_type = struct.pack(">b", 1)
    timestamp_packed = struct.pack(">Q", timestamp)
    tree_size_packed = struct.pack(">Q", tree_size)
    tree_head = version + signature_type + timestamp_packed + tree_size_packed + root_hash

    return create_signature(baseurl, tree_head, key=key)

def check_sct_signature(baseurl, signed_entry, sct, precert=False, publickey=None):
    if publickey == None:
        publickey = base64.decodestring(publickeys[baseurl])
    calculated_logid = hashlib.sha256(publickey).digest()
    received_logid = base64.b64decode(sct["id"])
    assert calculated_logid == received_logid, \
        "log id is incorrect:\n  should be %s\n        got %s" % \
        (base64.b64encode(calculated_logid),
         base64.b64encode(received_logid))
        # (calculated_logid.encode("hex_codec"),
        #  received_logid.encode("hex_codec"))

    signature = base64.decodestring(sct["signature"])

    version = struct.pack(">b", sct["sct_version"])
    signature_type = struct.pack(">b", 0)
    timestamp = struct.pack(">Q", sct["timestamp"])
    if precert:
        entry_type = struct.pack(">H", 1)
    else:
        entry_type = struct.pack(">H", 0)
    signed_struct = version + signature_type + timestamp + \
      entry_type + signed_entry + \
      tls_array(base64.decodestring(sct["extensions"]), 2)

    check_signature(baseurl, signature, signed_struct, publickey=publickey)

def pack_mtl(timestamp, leafcert):
    entry_type = struct.pack(">H", 0)
    extensions = ""

    timestamped_entry = struct.pack(">Q", timestamp) + entry_type + \
      tls_array(leafcert, 3) + tls_array(extensions, 2)
    version = struct.pack(">b", 0)
    leaf_type = struct.pack(">b", 0)
    merkle_tree_leaf = version + leaf_type + timestamped_entry
    return merkle_tree_leaf

def pack_mtl_precert(timestamp, cleanedcert, issuer_key_hash):
    entry_type = struct.pack(">H", 1)
    extensions = ""

    timestamped_entry = struct.pack(">Q", timestamp) + entry_type + \
      pack_precert(cleanedcert, issuer_key_hash) + tls_array(extensions, 2)
    version = struct.pack(">b", 0)
    leaf_type = struct.pack(">b", 0)
    merkle_tree_leaf = version + leaf_type + timestamped_entry
    return merkle_tree_leaf

def pack_precert(cleanedcert, issuer_key_hash):
    assert len(issuer_key_hash) == 32

    return issuer_key_hash + tls_array(cleanedcert, 3)

def pack_cert(cert):
    return tls_array(cert, 3)

def unpack_mtl(merkle_tree_leaf):
    version = merkle_tree_leaf[0:1]
    leaf_type = merkle_tree_leaf[1:2]
    timestamped_entry = merkle_tree_leaf[2:]
    (timestamp, entry_type) = struct.unpack(">QH", timestamped_entry[0:10])
    if entry_type == 0:
        issuer_key_hash = None
        (leafcert, rest_entry) = unpack_tls_array(timestamped_entry[10:], 3)
    elif entry_type == 1:
        issuer_key_hash = timestamped_entry[10:42]
        (leafcert, rest_entry) = unpack_tls_array(timestamped_entry[42:], 3)
    return (leafcert, timestamp, issuer_key_hash)

def get_leaf_hash(merkle_tree_leaf):
    leaf_hash = hashlib.sha256()
    leaf_hash.update(struct.pack(">b", 0))
    leaf_hash.update(merkle_tree_leaf)

    return leaf_hash.digest()

def timing_point(timer_dict=None, name=None):
    t = datetime.datetime.now()
    if timer_dict:
        starttime = timer_dict["lasttime"]
        stoptime = t
        deltatime = stoptime - starttime
        timer_dict["deltatimes"].append((name, deltatime.seconds * 1000000 + deltatime.microseconds))
        timer_dict["lasttime"] = t
        return None
    else:
        timer_dict = {"deltatimes":[], "lasttime":t}
        return timer_dict

def internal_hash(pair):
    if len(pair) == 1:
        return pair[0]
    else:
        hash = hashlib.sha256()
        hash.update(struct.pack(">b", 1))
        hash.update(pair[0])
        hash.update(pair[1])
        digest = hash.digest()
        return digest

def chunks(l, n):
    return [l[i:i+n] for i in range(0, len(l), n)]

def next_merkle_layer(layer):
    return [internal_hash(pair) for pair in chunks(layer, 2)]

def build_merkle_tree(layer0):
    if len(layer0) == 0:
        return [[hashlib.sha256().digest()]]
    layers = []
    current_layer = layer0
    layers.append(current_layer)
    while len(current_layer) > 1:
        current_layer = next_merkle_layer(current_layer)
        layers.append(current_layer)
    return layers

def print_inclusion_proof(proof):
    audit_path = proof[u'audit_path']
    n = proof[u'leaf_index']
    level = 0
    for s in audit_path:
        entry = base64.b16encode(base64.b64decode(s))
        n ^= 1
        print level, n, entry
        n >>= 1
        level += 1

def get_one_cert(store, i):
    filename = i / 10000
    zf = zipfile.ZipFile("%s/%04d.zip" % (store, i / 10000))
    cert = zf.read("%08d" % i)
    zf.close()
    return cert

def get_hash_from_certfile(cert):
    for line in cert.split("\n"):
        if line.startswith("-----"):
            return None
        if line.startswith("Leafhash: "):
            return base64.b16decode(line[len("Leafhash: "):])
    return None

def get_timestamp_from_certfile(cert):
    for line in cert.split("\n"):
        if line.startswith("-----"):
            return None
        if line.startswith("Timestamp: "):
            return int(line[len("Timestamp: "):])
    return None

def get_proof(store, tree_size, n):
    hash = get_hash_from_certfile(get_one_cert(store, n))
    return get_proof_by_hash(args.baseurl, hash, tree_size)

def get_certs_from_zipfiles(zipfiles, firstleaf, lastleaf):
    for i in range(firstleaf, lastleaf + 1):
        try:
            yield zipfiles[i / 10000].read("%08d" % i)
        except KeyError:
            return

def get_merkle_hash_64k(store, blocknumber, write_to_cache=False, treesize=None):
    firstleaf = blocknumber * 65536
    lastleaf = firstleaf + 65535
    if treesize != None:
        assert firstleaf < treesize
        usecache = lastleaf < treesize
        lastleaf = min(lastleaf, treesize - 1)
    else:
        usecache = True

    hashfilename = "%s/%04x.64khash" % (store, blocknumber)
    if usecache:
        try:
            hash = base64.b16decode(open(hashfilename).read())
            assert len(hash) == 32
            return ("hash", hash)
        except IOError:
            pass
    firstfile = firstleaf / 10000
    lastfile = lastleaf / 10000
    zipfiles = {}
    for i in range(firstfile, lastfile + 1):
        try:
            zipfiles[i] = zipfile.ZipFile("%s/%04d.zip" % (store, i))
        except IOError:
            break
    certs = get_certs_from_zipfiles(zipfiles, firstleaf, lastleaf)
    layer0 = [get_hash_from_certfile(cert) for cert in certs]
    tree = build_merkle_tree(layer0)
    calculated_hash = tree[-1][0]
    for zf in zipfiles.values():
        zf.close()
    if len(layer0) != lastleaf - firstleaf + 1:
        return ("incomplete", (len(layer0), calculated_hash))
    if write_to_cache:
        f = open(hashfilename, "w")
        f.write(base64.b16encode(calculated_hash))
        f.close()
    return ("hash", calculated_hash)

def get_tree_head(store, treesize):
    merkle_64klayer = []

    for blocknumber in range(0, (treesize / 65536) + 1):
        (resulttype, result) = get_merkle_hash_64k(store, blocknumber, treesize=treesize)
        if resulttype == "incomplete":
            print >>sys.stderr, "Couldn't read until tree size", treesize
            (incompletelength, hash) = result
            print >>sys.stderr, "Stopped at", blocknumber * 65536 + incompletelength
            # sys.exit(1)
            raise Exception
        assert resulttype == "hash"
        hash = result
        merkle_64klayer.append(hash)
        #print >>sys.stderr, print blocknumber * 65536,
        sys.stdout.flush()
    tree = build_merkle_tree(merkle_64klayer)
    calculated_root_hash = tree[-1][0]
    return calculated_root_hash

def get_intermediate_hash(store, treesize, level, index):
    if level >= 16:
        merkle_64klayer = []

        levelsize = (2**(level-16))

        for blocknumber in range(index * levelsize, (index + 1) * levelsize):
            if blocknumber * (2 ** 16) >= treesize:
                break
            #print "looking at block", blocknumber
            (resulttype, result) = get_merkle_hash_64k(store, blocknumber, treesize=treesize)
            if resulttype == "incomplete":
                print >>sys.stderr, "Couldn't read until tree size", treesize
                (incompletelength, hash) = result
                print >>sys.stderr, "Stopped at", blocknumber * 65536 + incompletelength
                # sys.exit(1)
                raise Exception
            assert resulttype == "hash"
            hash = result
            #print "block hash", base64.b16encode(hash)
            merkle_64klayer.append(hash)
            #print >>sys.stderr, print blocknumber * 65536,
            sys.stdout.flush()
        tree = build_merkle_tree(merkle_64klayer)
        return tree[-1][0]
    else:
        levelsize = 2 ** level
        firstleaf = index * levelsize
        lastleaf = firstleaf + levelsize - 1
        #print "firstleaf", firstleaf
        #print "lastleaf", lastleaf
        assert firstleaf < treesize
        lastleaf = min(lastleaf, treesize - 1)
        #print "modified lastleaf", lastleaf
        firstfile = firstleaf / 10000
        lastfile = lastleaf / 10000
        #print "files", firstfile, lastfile
        zipfiles = {}
        for i in range(firstfile, lastfile + 1):
            try:
                zipfiles[i] = zipfile.ZipFile("%s/%04d.zip" % (store, i))
            except IOError:
                break
        certs = get_certs_from_zipfiles(zipfiles, firstleaf, lastleaf)
        layer0 = [get_hash_from_certfile(cert) for cert in certs]
        #print "layer0", repr(layer0)
        tree = build_merkle_tree(layer0)
        calculated_hash = tree[-1][0]
        for zf in zipfiles.values():
            zf.close()
        assert len(layer0) == lastleaf - firstleaf + 1
        return calculated_hash

def bits(n):
    p = 0
    while n > 0:
        n >>= 1
        p += 1
    return p

def merkle_height(n):
    if n == 0:
        return 1
    return bits(n - 1)

def node_above((pathp, pathl), levels=1):
    return (pathp >> levels, pathl + levels)

def node_even((pathp, pathl)):
    return pathp & 1 == 0

def node_odd((pathp, pathl)):
    return pathp & 1 == 1

def node_lower((path1p, path1l), (path2p, path2l)):
    return path1l < path2l

def node_higher((path1p, path1l), (path2p, path2l)):
    return path1l > path2l

def node_level((path1p, path1l)):
    return path1l

def node_outside((path1p, path1l), (path2p, path2l)):
    assert path1l == path2l
    return path1p > path2p

def combine_two_hashes((path1, hash1), (path2, hash2), treesize):
    assert not node_higher(path1, path2)
    edge_node = (treesize - 1, 0)

    if node_lower(path1, path2):
        assert path1 == node_above(edge_node, levels=node_level(path1))
        while node_even(path1):
            path1 = node_above(path1)

    assert node_above(path1) == node_above(path2)
    assert (node_even(path1) and node_odd(path2)) or (node_odd(path1) and node_even(path2))

    if node_outside(path2, node_above(edge_node, levels=node_level(path2))):
        return (node_above(path1), hash1)

    if node_even(path1):
        newhash = internal_hash((hash1, hash2))
    else:
        newhash = internal_hash((hash2, hash1))

    return (node_above(path1), newhash)

def path_as_string(pos, level, treesize):
    height = merkle_height(treesize)
    path = "{0:0{width}b}".format(pos, width=height - level)
    if height == level:
        return ""
    return path

def nodes_for_subtree(subtreesize, treesize):
    height = merkle_height(treesize)
    nodes = []
    level = 0
    pos = subtreesize
    while pos > 0 and pos & 1 == 0:
        pos >>= 1
        level += 1
    if pos & 1:
        nodes.append((pos ^ 1, level))
    #print pos, level
    while level < height:
        pos_level0 = pos * (2 ** level)
        #print pos, level
        if pos_level0 < treesize:
            nodes.append((pos, level))
        pos >>= 1
        pos ^= 1
        level += 1
    return nodes

def nodes_for_index(pos, treesize):
    height = merkle_height(treesize)
    nodes = []
    level = 0
    pos ^= 1
    while level < height:
        pos_level0 = pos * (2 ** level)
        if pos_level0 < treesize:
            nodes.append((pos, level))
        pos >>= 1
        pos ^= 1
        level += 1
    return nodes

def verify_consistency_proof(consistency_proof, first, second, oldhash_input):
    if 2 ** bits(first - 1) == first:
        consistency_proof = [oldhash_input] + consistency_proof
    chain = zip(nodes_for_subtree(first, second), consistency_proof)
    assert len(nodes_for_subtree(first, second)) == len(consistency_proof)
    (_, hash) = reduce(lambda e1, e2: combine_two_hashes(e1, e2, second), chain)
    (_, oldhash) = reduce(lambda e1, e2: combine_two_hashes(e1, e2, first), chain)
    return (oldhash, hash)

def verify_inclusion_proof(inclusion_proof, index, treesize, leafhash):
    chain = zip([(index, 0)] + nodes_for_index(index, treesize), [leafhash] + inclusion_proof)
    assert len(nodes_for_index(index, treesize)) == len(inclusion_proof)
    (_, hash) = reduce(lambda e1, e2: combine_two_hashes(e1, e2, treesize), chain)
    return hash

def extract_original_entry(entry):
    leaf_input =  base64.decodestring(entry["leaf_input"])
    (leaf_cert, timestamp, issuer_key_hash) = unpack_mtl(leaf_input)
    extra_data = base64.decodestring(entry["extra_data"])
    if issuer_key_hash != None:
        (precert, extra_data) = extract_precertificate(extra_data)
        leaf_cert = precert
    certchain = decode_certificate_chain(extra_data)
    return ([leaf_cert] + certchain, timestamp, issuer_key_hash)

def mv_file(fromfn, tofn):
    shutil.move(fromfn, tofn)

def write_file(fn, sth):
    tempname = fn + ".new"
    open(tempname, 'w').write(json.dumps(sth))
    mv_file(tempname, fn)


class UTC(datetime.tzinfo):
    def utcoffset(self, dt):
      return datetime.timedelta(hours=0)
    def dst(self, dt):
        return datetime.timedelta(0)

def reduce_layer(layer):
    new_layer = []
    while len(layer) > 1:
        e1 = layer.pop(0)
        e2 = layer.pop(0)
        new_layer.append(internal_hash((e1,e2)))
    return new_layer

def reduce_tree(entries, layers):
    if len(entries) == 0 and layers is []:
        return [[hashlib.sha256().digest()]]
  
    layer_idx = 0
    layers[layer_idx] += entries

    while len(layers[layer_idx]) > 1:
        if len(layers) == layer_idx + 1:
            layers.append([])

        layers[layer_idx + 1] += reduce_layer(layers[layer_idx]) 
        layer_idx += 1
    return layers

def reduce_subtree_to_root(layers):
    while len(layers) > 1:
        if len(layers[1]) == 0:
            layers[1] = layers[0]
        else:
            layers[1] += next_merkle_layer(layers[0])
        del layers[0]

    if len(layers[0]) > 1:
        return next_merkle_layer(layers[0])
    return layers[0]

def verify_subtree(sth, subtree, base_url):
    try:
        tmp = deepcopy(subtree)
        root = base64.b64encode(reduce_subtree_to_root(tmp)[0])

        if root == sth["sha256_root_hash"]:
            return True
        else:
            return False
    except:
        return False

