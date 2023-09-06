import requests
import base64
import json
import csv
from csv import DictWriter
import datetime
import getpass
import urllib3
import pprint

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

##############################################################################################################################
#                                                     DYNAMIC VARIABLES                                                      #
##############################################################################################################################

mgrip = '192.168.17.140' # Provide the Manager IP
user = 'admin' # Provide the Manager API Username
password = 'password' # Provide the Manager API Username Password
filename = 'cvs_nsp_JSONGen_Policy_PolicyID' # Provide the filename
outpath = "C:\\Users\\LPinheir\\OneDrive - McAfee\\Personal Projects\\NSPRippen\\OUTPUT" # Provide the Path for the OUTPUT FILE
policyidlist = ["307"] # Update this list like this example: "policyidlist = ["307", "303", "200","250","320"]

##############################################################################################################################

# Function to encode the credentials em base64 as required by the IPS SDK
def fn_base64encode(u,p):
    userPass = '%s:%s' % (u,p)
    return base64.b64encode(bytes(userPass, 'utf-8'))

# Function to convert the data on the body response to a json (dict type)
def fn_convert_response_to_json(rsp):
    return json.loads(str(rsp, 'utf-8'))

# Function to request a resource with GET and return the response content in json format
def fn_get_request(resource):
    get_req = requests.get(url+resource, headers=headers,verify=False)
    return fn_convert_response_to_json(get_req.content)

# Function to request a resource with POST and return the response content in json format
def fn_post_request(resource,data):
    post_req = requests.post(url+resource, headers=headers, data=json.dumps(data))
    return post_req.content

# Function to logoff the session
def fn_logoff_session():
    logoff = requests.delete(url+'session', headers=headers)
    return fn_convert_response_to_json(logoff.content)

# Function to generate JSON File for each policy ID
def fn_get_policy():
    for x in policyidlist:
        policy = fn_get_request('ipspolicy/%s' % x)
        pprint.pprint(policy)
        with open('%s' % outpath + '%s' % filename + '%s' % x + '.json', 'w') as json_file:
            json.dump(policy, json_file)

##############################################################################################################################

url = ('https://%s/sdkapi/' % mgrip) #url = 'https://%s/sdkapi/' %input("Insert the Manager's Address: ") #NSM Address
headers = {'Accept':'application/vnd.nsm.v2.0+json','Content-Type':'application/json','NSM-SDK-API':''} #Parameters that needs to be sent on the Header of the api request
date = datetime.datetime.now().strftime("%Y-%m-%d--%H-%M-%S") #Get the current time
credencial_encoded = fn_base64encode(user, password)#fn_base64encode(user, getpass.getpass("Password: ")) #insert user and password and encodes it with function
headers['NSM-SDK-API'] = str(credencial_encoded, 'utf-8') #Updates Header Parameters with the proper credentials
authenticate = fn_get_request('session') #Make the request to authenticate the conection and get the session token
logged_session = fn_base64encode(authenticate['session'], authenticate['userId']) #Encodes to base64 the session token and user id
headers['NSM-SDK-API'] = str(logged_session, 'utf-8') #Updates Header Parameters with the proper session token

fn_get_policy()
