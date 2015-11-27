import json
import urllib2
import ssl

class sslparameters:
    sslcontext = None

def get_opener():
    try:
        opener = urllib2.build_opener(urllib2.HTTPSHandler(context=sslparameters.sslcontext))
    except TypeError:
        opener = urllib2.build_opener(urllib2.HTTPSHandler())
    return opener

def urlopen(url, data=None):
    return get_opener().open(url, data)

def get_sth(baseurl):
    result = urlopen(baseurl + "gaol/v1/get-sth").read()
    return json.loads(result)


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