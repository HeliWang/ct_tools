import datetime
import time

import base64
import struct

import hashlib
import ecdsa

try:
    from certkeys import publickeys
    import ecdsa
    from Crypto.Hash import SHA256
    import Crypto.PublicKey.RSA as RSA
    from Crypto.Signature import PKCS1_v1_5
except:
    print "Some imports failed, some functionality may be unavailable"


class UTC(datetime.tzinfo):
    def utcoffset(self, dt):
      return datetime.timedelta(hours=0)
    def dst(self, dt):
        return datetime.timedelta(0)

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


def time_str(ts = None):
    if ts is None:
        return datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    else:
        return datetime.datetime.fromtimestamp(ts / 1000, UTC()).strftime("%Y-%m-%d %H:%M:%S")

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

def decode_signature(signature):
    (hash_alg, signature_alg) = struct.unpack(">bb", signature[0:2])
    (unpacked_signature, rest) = unpack_tls_array(signature[2:], 2)
    assert rest == ""
    return (hash_alg, signature_alg, unpacked_signature)

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

        rsa_key = RSA.importKey(publickey)
        verifier = PKCS1_v1_5.new(rsa_key)
        assert verifier.verify(h, unpacked_signature), \
            "could not verify RSA signature"

def check_sth_signature(baseurl, sth, publickey=None):
    signature = base64.decodestring(sth["tree_head_signature"])

    version = struct.pack(">b", 0)
    signature_type = struct.pack(">b", 1)
    timestamp = struct.pack(">Q", sth["timestamp"])
    tree_size = struct.pack(">Q", sth["tree_size"])
    hash = base64.decodestring(sth["sha256_root_hash"])
    tree_head = version + signature_type + timestamp + tree_size + hash

    check_signature(baseurl, signature, tree_head, publickey=publickey)


def verify_consistency_proof(consistency_proof, first, second, oldhash_input):
    if 2 ** bits(first - 1) == first:
        consistency_proof = [oldhash_input] + consistency_proof
    chain = zip(nodes_for_subtree(first, second), consistency_proof)
    assert len(nodes_for_subtree(first, second)) == len(consistency_proof)
    (_, hash) = reduce(lambda e1, e2: combine_two_hashes(e1, e2, second), chain)
    (_, oldhash) = reduce(lambda e1, e2: combine_two_hashes(e1, e2, first), chain)
    return (oldhash, hash)


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
