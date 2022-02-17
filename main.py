import json
import requests
import configparser
import time
import os
import psycopg2
from requests.auth import HTTPBasicAuth

config = configparser.ConfigParser()
config.read('config.cfg')

# LOCAL FILE
filename = config.get('CONFIG', 'ArtifactFile')
open(filename, 'w').close()  # empty the file

# POSTGRESQL DB INITIALIZATION
SQLServer = config.get('CONFIG', 'SQLServer')
SQLPort = config.get('CONFIG', 'SQLPort')
SQLUsername = config.get('CONFIG', 'SQLUsername')
SQLPassword = config.get('CONFIG', 'SQLPassword')
SQLDatabase = config.get('CONFIG', 'SQLDatabase')
connection = psycopg2.connect(
    database=SQLDatabase, user=SQLUsername, password=SQLPassword, host=SQLServer, port=SQLPort
)
connection.autocommit = True
cursor = connection.cursor()  # The cursor object is a read-only pointer that allows a program to access the result set of a query
# SQL query
cursor.execute("DROP TABLE IF EXISTS ARTIFACT")  # Reset the db for TESTING purpose
query = '''CREATE TABLE IF NOT EXISTS ARTIFACT(
    Type TEXT NOT NULL,
    Value TEXT NOT NULL,
    Description TEXT,
    IncidentID TEXT
)'''
# Executing a query
cursor.execute(query)

# RESILIENT API INITIALIZATION
APIkeyID = config.get('CONFIG', 'APIkeyID')
APIkeySecret = config.get('CONFIG', 'APIkeySecret')
ResilientServer = config.get('CONFIG', 'ResilientServer')
org_id = config.get('CONFIG', 'OrganizationID')
headers = {
    "Content-Type": "application/json; charset=UTF-8"}
auth = HTTPBasicAuth(APIkeyID, APIkeySecret)


def convert_epochtime(datetime):
    pattern = '%d.%m.%Y'
    os.environ['TZ'] = 'UTC'
    epoch_time = int(
        time.mktime(time.strptime(datetime, pattern)))
    return epoch_time * 1000  # convert in millisecond, because create_date is in millisecond


def Get_Incidents(list_incidentID, epochtime):
    Resource = "rest/orgs/{0}/incidents".format(org_id)
    url = "https://{0}/{1}".format(ResilientServer,
                                   Resource)
    request = requests.get(url, headers=headers, auth=auth,
                           verify=True)  # Get request to the specified URL
    if request.status_code == 200:
        listjson_incident = request.json()
        list_incident = json.loads(
            json.dumps(listjson_incident))
        list_incidentID = []
        for i in list_incident:
            if i['create_date'] > epochtime and \
                    i['properties'][
                        'true_or_false_positive_dispensation'] == 896:  # 896:True Positive - 897: False Positive - 899: N/A
                print("ID: " + str(
                    i['id']) + " - " + "Name: " + str(
                    i['name']) + " - " + str(
                    i['properties'][
                        'true_or_false_positive_dispensation']))
                list_incidentID.append(i['id'])
    return list_incidentID


def Save_Artifact_File(filename, list_artifact):
    with open(filename, 'a') as file:
        if os.stat(
                filename).st_size == 0:  # If the file is empty
            file.write(
                "Type\tArtifact\tDescription\tIncidentID")
            file.write('\n')
        else:
            for k in range(len(list_artifact)):
                for j in list_artifact[k].values():
                    file.write(j + "\t")
                file.write("\n")


def Save_Artifact_DB(list_artifact):
    for j in list_artifact:
        insert_query = '''INSERT INTO artifact(
        Type, Value, Description, IncidentID) VALUES(
        %s, %s, %s, %s
        )'''
        tuple1 = (j.get('type'), j.get('value'), j.get('description'), j.get('incidentID'))
        cursor.execute(insert_query, tuple1)


datetime = '04.02.2022'  # set the earliest incident date, Format: %d.%m.%Y
epochtime = convert_epochtime(datetime)

list_incidentID = []
list_incidentID = Get_Incidents(list_incidentID, epochtime)
print("-------------- LIST INCIDENTS TP --------------")
for i in list_incidentID:
    print(i)

list_artifact_wanted = []

for j in list_incidentID:
    incident_id = j
    Resource = "rest/orgs/{0}/incidents/{1}/artifacts".format(
        org_id, incident_id)
    url = "https://{0}/{1}".format(ResilientServer,
                                   Resource)
    list_artifact = []
    request = requests.get(url, headers=headers, auth=auth,
                           verify=True)  # Get request to the specified URL

    if request.status_code == 200:
        # print(json.dumps(request.json(), indent=4, sort_keys=True)) #json.dumps() function converts a Python object into a json string
        print("-------TEST JSON into LIST------")
        result = json.loads(json.dumps(
            request.json()))  # load the json into a list, result become a list
        print('Artifact list :')
        for i in result:
            print("type: " + str(
                i['type']) + " - " + "value: " + str(
                i['value']) + " - " + "description: " + str(
                i['description']))
            list_artifact.append(
                {'type': i['type'], 'value': i['value'],
                 'description': i[
                     'description']})  # Put the type, the value and the description in a list of dictionaries
        print("---------TEST SPECIFIC ARTIFACT---------")
        list_type = [2, 3, 13, 31, 37,
                     1176]  # 2:DNS, 3:URL, 13:MD5Hash, 31:FileName, 37:FilePath, 1176:CommandString
        list_artifact_wanted = []
        for j in range(len(list_artifact)):
            if list_artifact[j]['type'] in list_type:
                #if list_artifact[j]['description'] is None:
                    if list_artifact[j]['type'] == 2:
                        list_artifact_wanted.append(
                            {'type': "DNS",
                             'value': list_artifact[j]['value'],
                             'description': "null" if list_artifact[j]['description'] is None else list_artifact[j]['description'],
                             'incidentID': str(incident_id)})
                    elif list_artifact[j]['type'] == 3:
                        list_artifact_wanted.append(
                            {'type': "URL",
                             'value': list_artifact[j]['value'],
                             'description': "null" if list_artifact[j]['description'] is None else list_artifact[j]['description'],
                             'incidentID': str(incident_id)})
                    elif list_artifact[j]['type'] == 13:
                        list_artifact_wanted.append(
                            {'type': "MD5Hash",
                             'value': list_artifact[j]['value'],
                             'description': "null" if list_artifact[j]['description'] is None else list_artifact[j]['description'],
                             'incidentID': str(incident_id)})
                    elif list_artifact[j]['type'] == 31:
                        list_artifact_wanted.append(
                            {'type': "FileName",
                             'value': list_artifact[j]['value'],
                             'description': "null" if list_artifact[j]['description'] is None else list_artifact[j]['description'],
                             'incidentID': str(incident_id)})
                    elif list_artifact[j]['type'] == 37:
                        list_artifact_wanted.append(
                            {'type': "FilePath",
                             'value': list_artifact[j]['value'],
                             'description': "null" if list_artifact[j]['description'] is None else list_artifact[j]['description'],
                             'incidentID': str(incident_id)})
                    elif list_artifact[j]['type'] == 1176:
                        list_artifact_wanted.append(
                            {'type': "CommandString",
                             'value': list_artifact[j]['value'],
                             'description': "null" if list_artifact[j]['description'] is None else list_artifact[j]['description'],
                             'incidentID': str(incident_id)})

        print("------------ WRITING IN FILE -------------")
        Save_Artifact_File(filename, list_artifact_wanted)
        print("--------- WRITING IN POSTGRESQL ----------")
        Save_Artifact_DB(list_artifact_wanted)

    else:
        print(request.status_code)
        
connection.close()
