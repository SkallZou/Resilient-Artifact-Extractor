import json
import requests
import configparser
import time
import os
from requests.auth import HTTPBasicAuth

config = configparser.ConfigParser()
config.read('config.cfg')

APIkeyID = config.get('CONFIG', 'APIkeyID')
APIkeySecret = config.get('CONFIG', 'APIkeySecret')
Server = config.get('CONFIG', 'Server')
headers = {"Content-Type" : "application/json; charset=UTF-8"}
auth = HTTPBasicAuth(APIkeyID, APIkeySecret)

def convert_epochtime(datetime):
    pattern = '%d.%m.%Y'
    os.environ['TZ']='UTC'
    epoch_time = int(time.mktime(time.strptime(datetime, pattern)))
    return epoch_time*1000 #convert in millisecond, because create_date is in millisecond

def Get_Incidents(list_incidentID, epochtime):
    Resource = "rest/orgs/202/incidents"
    url = "https://{0}/{1}".format(Server, Resource)
    request = requests.get(url, headers=headers, auth=auth, verify=True)  # Get request to the specified URL
    if request.status_code == 200:
        listjson_incident = request.json()
        list_incident = json.loads(json.dumps(listjson_incident))
        list_incidentID = []
        for i in list_incident:
            if i['create_date'] > epochtime and i['properties']['true_or_false_positive_dispensation'] == 896: #896:True Positive - 897: False Positive - 899: N/A
                print("ID: " + str(i['id']) + " - " + "Name: " + str(i['name']) + " - " + str(
                    i['properties']['true_or_false_positive_dispensation']))
                list_incidentID.append(i['id'])
    return list_incidentID

datetime = '21.01.2022' #set the earliest incident date, Format: %d.%m.%Y
epochtime = convert_epochtime(datetime)

list_incidentID = []
list_incidentID = Get_Incidents(list_incidentID, epochtime)
print("-------------- LIST INCIDENTS TP --------------")
for i in list_incidentID:
    print(i)

list_artifact_wanted = []

for j in list_incidentID:
    incident_id = j
    Resource = "rest/orgs/202/incidents/{0}/artifacts".format(incident_id)
    url = "https://{0}/{1}".format(Server, Resource)
    list_artifact = []
    request = requests.get(url, headers=headers, auth=auth, verify=True) #Get request to the specified URL

    if request.status_code == 200:
        #print(json.dumps(request.json(), indent=4, sort_keys=True)) #json.dumps() function converts a Python object into a json string
        print("-------TEST JSON into LIST------")
        result = json.loads(json.dumps(request.json())) #load the json into a list, result become a list
        print('Artifact list :')
        for i in result:
            print("type: " + str(i['type']) + " - " + "value: " + str(i['value']) + " - " + "description: " + str(i['description']))
            list_artifact.append({'type':i['type'], 'value':i['value'], 'description':i['description']}) #Put the type and the value in a list of dictionaries
        print("---------TEST SPECIFIC ARTIFACT---------")
        list_type = [2, 3, 13, 31, 37, 1176] #2:DNS, 3:URL, 13:MD5Hash, 31:FileName, 37:FilePath, 1176:CommandString
        for j in range(len(list_artifact)):
            if list_artifact[j]['type'] in list_type:
                #if list_artifact[j]['value'] not in list_artifact_wanted: #Avoid duplicates
                    print(list_artifact[j]['type'])
                    print(list_artifact[j]['value'])
                    if list_artifact[j]['type'] == 2:
                        list_artifact_wanted.append("DNS")
                    elif list_artifact[j]['type'] == 3:
                        list_artifact_wanted.append("URL")
                    elif list_artifact[j]['type'] == 13:
                        list_artifact_wanted.append("MD5Hash")
                    elif list_artifact[j]['type'] == 31:
                        list_artifact_wanted.append("FileName")
                    elif list_artifact[j]['type'] == 37:
                        list_artifact_wanted.append("FilePath")
                    elif list_artifact[j]['type'] == 1176:
                        list_artifact_wanted.append("CommandString")
                    list_artifact_wanted.append(list_artifact[j]['value']) #Put the wanted artifact in a new list to dump in a external file
                    if list_artifact[j]['description'] is None:
                        list_artifact_wanted.append("null")
                    else:
                        list_artifact_wanted.append(list_artifact[j]['description'])
                    list_artifact_wanted.append(str(incident_id))
        with open('ArtifactList.txt', 'w') as file:
            file.write("Type\tArtifact\tDescription\tIncidentID")
            file.write('\n')
            count = 0
            for k in list_artifact_wanted:
                file.write(k)
                count = count + 1
                if count%4 == 0:
                    file.write('\n')
                else:
                    file.write("\t")
            #json.dump(list_artifact_wanted, file) #json.dump() method extract a list to a file in JSON
    else:
        print(request.status_code)