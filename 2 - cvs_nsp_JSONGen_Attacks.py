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

mgrip = 'mgrip' # Provide the Manager IP
user = 'admin' # Provide the Manager API Username
password = 'password' # Provide the Manager API Username Password
filename = 'cvs_nsp_JSONGen_attacks' # Provide the filename
outpath = 'C:\\Users\\LPinheir\\OneDrive - McAfee\\Personal Projects\\NSPRippen' # Provide the Path for the OUTPUT FILE

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

# Function to request a list of Domains
def fn_get_domains():
    domains = fn_get_request('domain')
    pprint.pprint(domains)

# Function to request a list of Polices
def fn_get_attacks():
    attacks = fn_get_request('attacks')
    pprint.pprint(attacks)
    with open('%s' % outpath + '%s' % filename + '.json', 'w') as json_file:
        json.dump(attacks, json_file)

url = ('https://%s/sdkapi/' % mgrip) #url = 'https://%s/sdkapi/' %input("Insert the Manager's Address: ") #NSM Address
headers = {'Accept':'application/vnd.nsm.v2.0+json','Content-Type':'application/json','NSM-SDK-API':''} #Parameters that needs to be sent on the Header of the api request
date = datetime.datetime.now().strftime("%Y-%m-%d--%H-%M-%S") #Get the current time
credencial_encoded = fn_base64encode(user, password)#fn_base64encode(user, getpass.getpass("Password: ")) #insert user and password and encodes it with function
headers['NSM-SDK-API'] = str(credencial_encoded, 'utf-8') #Updates Header Parameters with the proper credentials
authenticate = fn_get_request('session') #Make the request to authenticate the conection and get the session token
logged_session = fn_base64encode(authenticate['session'], authenticate['userId']) #Encodes to base64 the session token and user id
headers['NSM-SDK-API'] = str(logged_session, 'utf-8') #Updates Header Parameters with the proper session token

fn_get_attacks()
