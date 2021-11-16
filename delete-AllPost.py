#!/usr/bin/env python3
import sys
import requests # pip install requests
import jwt	# pip install pyjwt
from datetime import datetime as date
import automationassets
from automationassets import AutomationAssetNotFound
#Parameters should be added in the following order
#API admin Key (eg. 6193ae96f1cf7d0001136164:f5ca17b77eb13136f7476444ac96b992464cbdf1dd9e40933b8eaec03c0b7b24)
#Ghost uri (eg. ghost-fd-5wzc7vgv7jnhm.azurefd.net)

# get a credential
#key = str(sys.argv[1])
key = automationassets.get_automation_variable('adminAPIKey')

# get admin API URL
#uri = str(sys.argv[2])
uri = automationassets.get_automation_variable('uri')
url = "https://" + uri + "/ghost/api/v3/admin/posts/"

# Split the key into ID and SECRET
id, secret = key.split(':')

# Prepare header and payload
iat = int(date.now().timestamp())

header = {'alg': 'HS256', 'typ': 'JWT', 'kid': id}
payload = {
    'iat': iat,
    'exp': iat + 5 * 60,
    'aud': '/v3/admin/'
}

# Create the token (including decoding secret)
token = jwt.encode(payload, bytes.fromhex(secret), algorithm='HS256', headers=header)

# Make an authenticated request to create a post
headers = {'Authorization': 'Ghost {}'.format(token.decode())}

def removePost():
    r = requests.get(url, headers=headers)
    response = r.json()
    if response["meta"]:
        if response["meta"]["pagination"]["total"] == 0:
            print("No more post -> return")
            return
    else:
        print(response)
        return
    
    if response["posts"]:
        for i in response["posts"]:
            print("Remove post with ID: ", i["id"])
            delete = url + i["id"] + "/"
            requests.delete(delete, headers=headers)
    
    print("Number of pages:", response["meta"]["pagination"]["total"])
    removePost()

removePost()
