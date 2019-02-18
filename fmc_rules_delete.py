#!/usr/bin/env python
# -*- coding: UTF-8 -*-# enable debugging

print """
--------------------
Copyright (c) 2019 Cisco and/or its affiliates.
This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.0 (the "License"). You may obtain a copy of the
License at
               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.
---------------------
"""

__author__ = "Dirk Woellhaf <dwoellha@cisco.com>"
__contributors__ = [
    "Dirk Woellhaf <dwoellha@cisco.com>"
]
__copyright__ = "Copyright (c) 2019 Cisco and/or its affiliates."
__license__ = "Cisco Sample Code License, Version 1.0"

import requests
import json
import sys
import os
import time
import ConfigParser
import base64
import logging
from datetime import datetime

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def FMC_Login(Settings):
  #print "FMC Login..."
  server = "https://"+Settings["FMC_IP"]
  
  r = None
  headers = {'Content-Type': 'application/json'}
  api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
  auth_url = server + api_auth_path
  r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(Settings["FMC_USER"], Settings["FMC_PWD"]), verify=False)
  if r.status_code == 204:
    print "FMC Login succesful. Token: "+str(r.headers["X-auth-access-token"])
    return r.headers["X-auth-access-token"]
  else:
    print "FMC Login failed. "+str(headers)+" "+r.text
    sys.exit()

def FMC_Logout(Settings):
    #print "FMC Logout..."
    api_path = "/api/fmc_platform/v1/auth/revokeaccess"
    # Create custom header for revoke access
    headers = {'X-auth-access-token' : Settings["FMC_X-auth-access-token"]}
    # log in to API
    post_response = requests.post("https://"+str(Settings["FMC_IP"])+api_path, headers=headers, verify=False)
    if post_response.status_code == 204:
      print "FMC Logout succesful. Token: "+str(headers["X-auth-access-token"])
    else:
      print "FMC Logout failed. "+str(headers)+" "+post_response.text

def FMC_Get(Settings, api_path):
  #print "Reading from FMC..."
  #print "FMC GET"

  server = "https://"+Settings["FMC_IP"]


  url = server + api_path
  if (url[-1] == '/'):
      url = url[:-1]
  headers = {'X-auth-access-token' : Settings["FMC_X-auth-access-token"]}

  # GET OPERATION


  try:
      # REST call with SSL verification turned off:
      r = requests.get(url, headers=headers, verify=False)
      status_code = r.status_code
      resp = r.text
      json_resp = json.loads(resp)
      if (status_code == 200):
          #print("GET successful. Response data --> ")
          return json_resp
      else:
          r.raise_for_status()
          print("Error occurred in GET")
          print json_resp["error"]["severity"]+": "+json_resp["error"]["messages"][0]["description"]
  except requests.exceptions.HTTPError as err:
      print ("Error in connection --> "+str(err))
      print ("Error occurred in GET")
      print json_resp["error"]["severity"]+": "+json_resp["error"]["messages"][0]["description"]
  finally:
      if r : r.close()

def FMC_Delete(Settings, api_path):
  server = "https://"+Settings["FMC_IP"]

  url = server + api_path
  if (url[-1] == '/'):
      url = url[:-1]

  headers = {'X-auth-access-token' : Settings["FMC_X-auth-access-token"]}
  r = requests.delete(url, headers=headers, verify=False)
  resp = r.text
  #print("Status code is: "+str(status_code))
  if r.status_code == 200 or r.status_code == 201 or r.status_code == 202:
      json_resp = json.loads(resp)
      if "id" in json_resp:
        #print "FMC POST succesful for Object "+json_resp["id"]
        return json_resp["id"]
      else:
        print "FMC DELETE succesful."

  elif status_code == 400:
      json_resp = json.loads(resp)
      print json_resp["error"]["severity"]+": "+json_resp["error"]["messages"][0]["description"]
      #{"error":{"category":"FRAMEWORK","messages":[{"description":
  else :
      print "FMC DELETE failed: "+str(r.status_code)+":"+resp
      sys.exit()

if __name__ == "__main__":
    Settings={}
    HostList=[]
    OldHosts = []

    Settings["FMC_IP"] = "10.1.17.27"
    Settings["FMC_USER"] = "apiuser"
    Settings["FMC_PWD"] = "password"
    
    Settings["FMC_X-auth-access-token"] = FMC_Login(Settings)
    ExistingHosts = FMC_Get(Settings, "/api/fmc_config/v1/domain/default/object/hosts?limit=4000")
    Filter = sys.argv[1]

    for Host in ExistingHosts["items"]:
      if Filter in Host["name"]:
        OldHosts.append(Host["id"])

    print str(len(OldHosts))+" Hosts found matching Filter."
    #print OldHosts
    for Host in OldHosts:
      r = FMC_Delete(Settings,"/api/fmc_config/v1/domain/default/object/hosts/"+Host)
      if r != None:
        print r+" deleted."


    
    FMC_Logout(Settings)