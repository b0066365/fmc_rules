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

def FMC_Post(Settings, fmc_data, api_path):
  time.sleep(0.8)
  #print "FMC POST Data:"+str(fmc_data)

  server = "https://"+Settings["FMC_IP"]

  url = server + api_path
  if (url[-1] == '/'):
      url = url[:-1]
  headers = {'X-auth-access-token' : Settings["FMC_X-auth-access-token"]}
  # POST OPERATION
  # REST call with SSL verification turned off:
  r = requests.post(url, json=fmc_data, headers=headers, verify=False)
  status_code = r.status_code
  resp = r.text
  #print("Status code is: "+str(status_code))
  if status_code == 200 or status_code == 201 or status_code == 202:
      json_resp = json.loads(resp)
      if "id" in json_resp:
        #print "FMC POST succesful for Object "+json_resp["id"]
        return json_resp["id"]
      else:
        print "FMC POST succesful."

  elif status_code == 400:
      json_resp = json.loads(resp)
      print json_resp["error"]["severity"]+": "+json_resp["error"]["messages"][0]["description"]
      #{"error":{"category":"FRAMEWORK","messages":[{"description":
  else :
      print "FMC POST failed: "+str(r.status_code)+":"+resp
      sys.exit()

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

def GetAccessPolicies(Settings):
  AccessPolicies = FMC_Get(Settings, "/api/fmc_config/v1/domain/default/policy/accesspolicies")

  for AccessPolicy in AccessPolicies["items"]:
    if Settings["FMC_ACPNAME"] == AccessPolicy["name"]:
      return AccessPolicy["id"]

def GetExistingHostID(NewHost, ExistingHosts):
  for ExistingHost in ExistingHosts["items"]:   
    #print ExistingHost["name"] 
    if NewHost == ExistingHost["name"]:
      #print ExistingHost["name"]
      return ExistingHost["id"]

def CreateACP(Settings):
  fmc_data = {
      "type": "AccessPolicy",
      "name": Settings["FMC_ACPNAME"],
      "defaultAction": {
        "action": "TRUST"
      }
  }
  
  r = FMC_Post(Settings, fmc_data, "/api/fmc_config/v1/domain/default/policy/accesspolicies")
  if r == None:
    print "No New Policy created"
    return GetAccessPolicies(Settings)
    #return None
  else:
    return r

def CreateHosts(Settings, HostList):
  NewHosts={}
  fmc_data=[]
  ExistingHosts = FMC_Get(Settings, "/api/fmc_config/v1/domain/default/object/hosts?limit=4096")
  print "Pulled "+str(len(ExistingHosts["items"]))+" Hosts from FMC"  

  for Host in HostList:
    currentHost = Host
    if ":" in currentHost:
      IpType = "IPv6_"
    else:
      IpType = "IPv4_"

    Hostname = Settings["HOSTPREFIX"]+IpType+currentHost
    if IpType == "IPv6_":
      Hostname = Hostname.replace(":", "-")

    HostObject = {
      "name": Hostname,
      "type": "Host",
      "value": currentHost
    }
    #print fmc_data

    if GetExistingHostID(Hostname, ExistingHosts) != None:  
      #print "Gettting existing Hosts ID"
      NewHosts[Hostname]=GetExistingHostID(Hostname, ExistingHosts)
      print "Existing Host: "+Hostname+" - ID: "+NewHosts[Hostname]
    else:
      print "Adding new Host: "+Hostname
      fmc_data.append(HostObject)

  if len(fmc_data) >=1:  
    if len(fmc_data) <= 1000:
      print "Will deploy "+str(len(fmc_data))+" Hosts"
      FMC_Post(Settings, fmc_data, "/api/fmc_config/v1/domain/default/object/hosts?bulk=true")
    else:
      print "Too many Objects in FMC_Data Array!! Exiting. "
      sys.exit()
  

  ExistingHosts = FMC_Get(Settings, "/api/fmc_config/v1/domain/default/object/hosts?limit=4096")
  print "Pulled "+str(len(ExistingHosts["items"]))+" Hosts from FMC" 

  for Host in HostList:
    currentHost = Host
    if ":" in currentHost:
      IpType = "IPv6_"
    else:
      IpType = "IPv4_"

    Hostname = Settings["HOSTPREFIX"]+IpType+currentHost
    if IpType == "IPv6_":
      Hostname = Hostname.replace(":", "-")

    if GetExistingHostID(Hostname, ExistingHosts) != None:  
      #print "Gettting existing Hosts ID"
      NewHosts[Hostname]=GetExistingHostID(Hostname, ExistingHosts)
      print "Existing Host: "+Hostname+" - ID: "+NewHosts[Hostname]
    else:
      print "Host Object not found!"+Hostname

    

  return NewHosts

def CreateACPEntry(Settings, NewHosts):
  fmc_data=[]
  for Host in NewHosts:
    print Host+": "+str(NewHosts[Host])
    
    acp_rule = {
      "action": "BLOCK",
      "enabled": True,
      "type": "AccessRule",
      "name": Host,
      "sourceNetworks": {
        "objects": [
          {
          	"type": "Group",
            "name": "any"
          }
        ]
      },
      "destinationNetworks": {
        "objects": [
          {
          	"type": "Host",
            "name": Host,
            "id": str(NewHosts[Host])
          }
        ]
      },
      "newComments": [
        Host+": "+str(NewHosts[Host])
      ]
    }
    if NewHosts[Host] != None:
      fmc_data.append(acp_rule)
    else:
      print "Skipping ACP Entry."

  if len(fmc_data) >=1:  
    if len(fmc_data) <= 1000:
      print "Will deploy "+str(len(fmc_data))+" Access Policies into Policy: "+str(Settings["FMC_ACPID"])
      FMC_Post(Settings, fmc_data, "/api/fmc_config/v1/domain/default/policy/accesspolicies/"+str(Settings["FMC_ACPID"])+"/accessrules?bulk=true")
    else:
      print "Too many Objects in FMC_Data Array!! Exiting. "
      sys.exit()
  else:
    print "No New ACP Rules to create."

if __name__ == "__main__":
    Settings={}
    NewHosts={}
    HostList=[]
      
    Settings["LOG_DIR"] = "/home/app/log"
    Settings["LOG_LEVEL"] = "debug"
    Settings["FMC_IP"] = "10.1.17.27"
    Settings["FMC_USER"] = "apiuser"
    Settings["FMC_PWD"] = "password"
    Settings["FMC_ACPNAME"] = "CUSTOMER.Policy"
    Settings["HOSTFILE"] = sys.argv[1]
    Settings["HOSTPREFIX"] = "CUST_"

    
    Settings["FMC_X-auth-access-token"] = FMC_Login(Settings)

    Hostfile = open(Settings["HOSTFILE"], "r")
    for line in Hostfile:
      HostList.append(line.strip("\n"))

    print "Got "+str(len(HostList))+" Hosts from File: "+Settings["HOSTFILE"]    

    NewHosts=CreateHosts(Settings, HostList)
    print "Pausing 5sec..."
    time.sleep(5)

    Settings["FMC_ACPID"]=CreateACP(Settings)

    if Settings["FMC_ACPID"] != None:
      print ":"
      CreateACPEntry(Settings, NewHosts)
    else:
      print "NO ACP-ID specified! Exiting!"
      sys.exit()

    FMC_Logout(Settings)