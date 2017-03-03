import os
import sys
import requests
import json
# You'll need to install the following modules
# I used PyCrypto which can be installed manually or using "pip install pycrypto"
import binascii
import Crypto
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from base64 import b64decode
#If you want to use AWS KMS for encrypting/decrypting your username/password you'll need boto3
#import boto3

tab_server_url = raw_input("Enter your Tableau Server URL:")
tableau_username = raw_input("Enter your username: ")
tableau_password = raw_input("Input your password: ")

#Set UP KMS Client
#kms = boto3.client('kms')
#keyid = ARN from KMS
#You should store your username/password in encrypted form, in S3, Dynamo, or other DB
#Fetch them with the appropriate Boto Context, then decrypt
#If you store the entire Python Dict, then you'll need to do this
#cipher = Dict.get('CiphertextBlob')
#otherwise, you can just decrypt the blob like this
#username_decrypt = kms.decrypt(CiphertextBlob=cipher)
#then substitute tableau_username with username_decrypt
#repeat for tableau_password


def _encode_for_display(text):
    """
    Encodes strings so they can display as ASCII in a Windows terminal window.
    This function also encodes strings for processing by xml.etree.ElementTree functions.
    Returns an ASCII-encoded version of the text.
    Unicode characters are converted to ASCII placeholders (for example, "?").
    """
    return text.encode('ascii', errors="backslashreplace").decode('utf-8')

# Establish a session so we can retain the cookies
session = requests.Session()

def generatePublicKey():
      payload = "{\"method\":\"generatePublicKey\",\"params\":{}}"
      endpoint = "generatePublicKey"
      url = tab_server_url + "/vizportal/api/web/v1/"+endpoint
      headers = {
      'content-type': "application/json;charset=UTF-8",
      'accept': "application/json, text/plain, */*",
      'cache-control': "no-cache"
      }
      response = session.post(url, data=payload, headers=headers)
      response_text = json.loads(_encode_for_display(response.text))
      response_values = {"keyId":response_text["result"]["keyId"], "n":response_text["result"]["key"]["n"],"e":response_text["result"]["key"]["e"]}
      return response_values

# Generate a pubilc key that will be used to encrypt the user's password
public_key = generatePublicKey()
pk = public_key["keyId"]


# Encrypt with RSA public key (it's important to use PKCS11)
def assymmetric_encrypt(val, public_key):
     modulusDecoded = long(public_key["n"], 16)
     exponentDecoded = long(public_key["e"], 16)
     keyPub = RSA.construct((modulusDecoded, exponentDecoded))
     # Generate a cypher using the PKCS1.5 standard
     cipher = PKCS1_v1_5.new(keyPub)
     return cipher.encrypt(val)

# Encrypt the password used to login
encryptedPassword = assymmetric_encrypt(tableau_password,public_key)

def vizportalLogin(encryptedPassword, keyId):
     encodedPassword = binascii.b2a_hex(encryptedPassword)
     payload = "{\"method\":\"login\",\"params\":{\"username\":\"%s\", \"encryptedPassword\":\"%s\", \"keyId\":\"%s\"}}" % (tableau_username, encodedPassword,keyId)
     endpoint = "login"
     url = tab_server_url + "/vizportal/api/web/v1/"+endpoint
     headers = {
     'content-type': "application/json;charset=UTF-8",
     'accept': "application/json, text/plain, */*",
     'cache-control': "no-cache"
     }
     response = session.post(url, data=payload, headers=headers)
     return response


def getSessionInfo(xsrf_token):
    payload = "{\"method\":\"getSessionInfo\",\"params\":{}}"
    endpoint = "getSessionInfo"
    url = tab_server_url + "/vizportal/api/web/v1/"+endpoint
    # print url
    headers = {
    'content-type': "application/json;charset=UTF-8",
    'accept': "application/json, text/plain, */*",
    'cache-control': "no-cache",
    'X-XSRF-TOKEN':xsrf_token
    }
    SessionResponse = session.post(url, data=payload, headers=headers)
    # return response.cookies
    return SessionResponse

def DetectTableauVersion():
    global xsrf_token
    # xsrf_token, workgroup_session_id = login_to_vizportal()
    TabServerSession = getSessionInfo(xsrf_token).text
    TSS = json.loads(TabServerSession)
    v = TSS['result']['server']['version']['externalVersion']
    major = v['major']
    minor = v['minor']
    patch = v['patch']
    tsVersion = major+'.'+minor
    api_version = None

    api_versions = requests.get('https://tbevdbgwch.execute-api.us-west-2.amazonaws.com/Production/versions/')
    api_lookup = json.loads(api_versions.text)
    # print api_lookup
    for k,v in api_lookup['server'].iteritems():
        if k == tsVersion:
            #print v
            api_version = v
    return tsVersion, api_version

login_response = vizportalLogin(encryptedPassword, pk)
if login_response.status_code == 200:
    print "Login to Vizportal Successful!"

# print login_response.headers
sc = login_response.headers["Set-Cookie"]
set_cookie = dict(item.split("=") for item in sc.split(";"))
xsrf_token, workgroup_session_id = set_cookie[" HttpOnly, XSRF-TOKEN"], set_cookie["workgroup_session_id"]


#Use this for connections with SSL
#sc = login_response.headers["Set-Cookie"]
# headers = []
# for item in sc.split(";"):
#     print item
#     if "workgroup" in item:
#         headers.append(item.split("=")[1])
#     elif "XSRF" in item:
#         headers.append(item.split("=")[1])
# workgroup_session_id, xsrf_token = headers[0], headers[1]


tsVersion, api_version = DetectTableauVersion()
print "Tableau Server Version: %s" % (tsVersion)
print "API Version: %s" % (api_version)
