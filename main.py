import json
import requests
import configparser
from requests.auth import HTTPBasicAuth

config = configparser.ConfigParser()
config.read('config.cfg')

APIkeyID = config.get('CONFIG', 'APIkeyID')
APIkeySecret = config.get('CONFIG', 'APIkeySecret')
Server = config.get('CONFIG', 'Server')
headers = {"Content-Type" : "application/json; charset=UTF-8"}
auth = HTTPBasicAuth(APIkeyID, APIkeySecret)

def Get_Incidents(list_incidentID):
    Resource = "rest/orgs/202/incidents"
    url = "https://{0}/{1}".format(Server, Resource)
    request = requests.get(url, headers=headers, auth=auth, verify=False)  # Get request to the specified URL
    if request.status_code == 200:
        listjson_incident = request.json()
        list_incident = json.loads(json.dumps(listjson_incident))
        list_incidentID = []
        for i in list_incident:
            if i['create_date'] > 1642801625194 and i['properties']['true_or_false_positive_dispensation'] == 896:
                print(str(i['id']) + " - " + str(i['name']) + " - " + str(
                    i['properties']['true_or_false_positive_dispensation']))
                list_incidentID.append(i['id'])
        return list_incidentID


list_incidentID = []
list_incidentID = Get_Incidents(list_incidentID)
print("-------------- LIST INCIDENTS TP --------------")
for i in list_incidentID:
    print(i)

#add loop there
incident_id = "40386"
Resource = "rest/orgs/202/incidents/{0}/artifacts".format(incident_id)
url = "https://{0}/{1}".format(Server, Resource)
list_artifact = []
request = requests.get(url, headers=headers, auth=auth, verify=False) #Get request to the specified URL

if request.status_code == 200:
    #print(json.dumps(request.json(), indent=4, sort_keys=True)) #json.dumps() function converts a Python object into a json string
    print("-------TEST JSON into LIST------")
    result = json.loads(json.dumps(request.json())) #load the json into a list, result become a list
    print('Artifact list :')
    for i in result:
        print(i['type'])
        print(i['value'])
        list_artifact.append({'type':i['type'], 'value':i['value']}) #Put the type and the value in a list of dictionaries
    print("---------TEST SPECIFIC ARTIFACT---------")
    list_type = [2, 3, 13, 31, 37, 1176] #2:DNS, 3:URL, 13:MD5Hash, 31:FileName, 37:FilePath, 1176:CommandString
    list_artifact_wanted = []
    for j in range(len(list_artifact)):
        if(list_artifact[j]['type'] in list_type):
            print(list_artifact[j]['value'])
            list_artifact_wanted.append(list_artifact[j]['value']) #Put the wanted artifact in a new list to dump in a external file
    with open('ArtifactList.txt', 'w') as file:
        json.dump(list_artifact_wanted, file) #json.dump() method extract a list to a file in JSON

else:
    print(request.status_code)