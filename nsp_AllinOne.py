import requests
import base64
import json
import datetime
import getpass
import urllib3
import pprint
import getopt, sys
import argparse
import ast

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

##############################################################################################################################
#                                                     DYNAMIC VARIABLES                                                      #
##############################################################################################################################

mgrip = 'mgrip' # Provide the Manager IP
user = 'admin' # Provide the Manager API Username
password = 'password' # Provide the Manager API Username Password
pfilename = 'cvs_nsp_JSONGen_Policy_PolicyID' # Provide the filename
afilename = 'cvs_nsp_JSONGen_attacks' # Provide the filename
alfilename = 'cvs_nsp_JSONGen_alerts' # Provide the filename
outpath = 'C:\\Users\\LPinheir\\OUTPUT\\' # Provide the Path for the OUTPUT FILE
#policyidlist = ["301", "303"] # Update this list like this example: "policyidlist = ["307", "303", "200","250","320"]

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

# Function to Show Policy Names
def fn_get_policiesname():
    print(" ")
    domain_id = input('Please, type the Domain ID: ')
    print(" ")
    policies = fn_get_request('domain/%s/ipspolicies' % domain_id)
    resp = ("""%s""" % policies)
    response = resp.replace("True", "'True'").replace("False", "'False'").replace("'", '"')
    response = json.loads(response)
    for x in response['PolicyDescriptorDetailsList']:
        polid = (x['policyId'])
        polname = (x['name'])
        print ( " " , + polid ,'-', polname)
    
# Function to request a list of Polices
def fn_get_attacks():
    attacks = fn_get_request('attacks')
    pprint.pprint(attacks)
    with open('%s' % outpath + '%s' % afilename + '.json', 'w') as json_file:
        json.dump(attacks, json_file)

#def fn_set_polist():
    #input_string = input("Enter Policy ID separated by comma: ")
#    input_string = input()
#   policyidlist  = input_string.split(",")

#    print(policyidlist)

# Function to generate JSON File for each policy ID
def fn_get_policy():
    print("JSON Files will be generated for the following Policy IDs '%s'" % policyidlist)
    for x in policyidlist:
        policy = fn_get_request('ipspolicy/%s' % x)
        pprint.pprint(policy)
        with open('%s' % outpath + '%s' % pfilename + '%s' % x + '.json', 'w') as json_file:
            json.dump(policy, json_file)

# Function to generate JSON File alers
def fn_get_alerts():
    print("JSON File will be generated for the last 14 days Attack Log")
    alerts = fn_get_request('alerts?domainId=0&includeChildDomain=true&alertstate=Unacknowledged&timeperiod=LAST_14_DAYS')
    pprint.pprint(alerts)
    with open('%s' % outpath + '%s' % alfilename + '.json', 'w') as json_file:
        json.dump(alerts, json_file)


def fn_help():
        print(" ")
        print("-------------------------------------------------------------------HELP----------------------------------------------------------------------")
        print(" ")
        print(" ")
        print("   -i    The '-i' Parameter will provide you a list of your current domains IDs included in your NSM ")
        print("         and an list of the policies included in each domain ")
        #print(" ")
        #print("   -p    The '-p' parameter will generate a JSON file for each policy ID")
        print(" ")
        print("   -a    The '-a' parameter will generate a JSON file from the current Master Repository Attacks in your NSM it includes also covered CVEs")
        print(" ")
        print("   -l    The '-l' parameter will generate a JSON file from the last 14 days alerts")
        print(" ")
        print("   -s    The '-s' will generate a JSON file for each policy ID")
        print("         Usage: csv_nsp_JSON_AllinOne.py -s 200 205 305       ")
        print(" ")
        print("   -h    The '-h' Help")
        print(" ")
        print(" ")
        print("-----------------------------------------------------------------------------------------------------------------------------------------------")

##############################################################################################################################

url = ('https://%s/sdkapi/' % mgrip) #url = 'https://%s/sdkapi/' %input("Insert the Manager's Address: ") #NSM Address
headers = {'Accept':'application/vnd.nsm.v2.0+json','Content-Type':'application/json','NSM-SDK-API':''} #Parameters that needs to be sent on the Header of the api request
date = datetime.datetime.now().strftime("%Y-%m-%d--%H-%M-%S") #Get the current time
credencial_encoded = fn_base64encode(user, password)#fn_base64encode(user, getpass.getpass("Password: ")) #insert user and password and encodes it with function
headers['NSM-SDK-API'] = str(credencial_encoded, 'utf-8') #Updates Header Parameters with the proper credentials
authenticate = fn_get_request('session') #Make the request to authenticate the conection and get the session token
logged_session = fn_base64encode(authenticate['session'], authenticate['userId']) #Encodes to base64 the session token and user id
headers['NSM-SDK-API'] = str(logged_session, 'utf-8') #Updates Header Parameters with the proper session token

# Remove 1st argument from the 
# list of command line arguments 
argumentList = sys.argv[1:] 

# Options 
options = "ipalsh_:"

# Long options 
long_options = ["info", "pol", "att", "alert", "set", "help"] 

try: 
    # Parsing argument 
    arguments, values = getopt.getopt(argumentList, options, long_options) 
    policyidlist  = []
    
    # checking each argument
    for currentArgument, currentValue in arguments: 

        if currentArgument in ("-i", "--info"):
            fn_get_domains()
            print(" ")
            fn_get_policiesname()
        elif currentArgument in ("-p", "--pol"): 
            fn_get_policy()
        elif currentArgument in ("-a", "--att"): 
            fn_get_attacks()
        elif currentArgument in ("-l", "--alert"): 
            fn_get_alerts()
        elif currentArgument in ("-s", "--set"): 
            policyidlist = values
            if not policyidlist:
                print(" ")
                print("The Policy ID was not specified:")
                print(" ")
                print("   -s    The '-s' will generate a JSON file for each policy ID")
                print("         Usage: csv_nsp_JSON_AllinOne.py -s 200 205 305       ")
            else:
                fn_get_policy()
                
        elif currentArgument in ("-h", "--help"): 
            fn_help()
                        
except getopt.error as err: 
    # output error, and return with an error code 
    print (str(err))

