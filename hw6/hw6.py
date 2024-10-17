import requests
from zipfile import ZipFile
from io import BytesIO
import pandas as pd
from pandas.io import json
#Download Dataset
url = ('https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets'
'/atomic/windows/lateral_movement/host/empire_psremoting_stager.zip')
zipFileRequest = requests.get(url)
zipFile = ZipFile(BytesIO(zipFileRequest.content))
datasetJSONPath = zipFile.extract(zipFile.namelist()[0])
#Read Dataset
df = json.read_json(path_or_buf=datasetJSONPath, lines=True)
#Analytic I
print('=======================================================Analytic I=====================================================================================================')
print(
df[['@timestamp','Hostname','Channel']]

[(df['Channel'].isin(['Microsoft-Windows-PowerShell/Operational','Windows PowerShell']))
    & (df['EventID'].isin([400,4103]))
    & (df['Message'].str.contains('.*HostApplication.*wsmprovhost.*', regex=True))
]
.head()
)

#Analytic II
print('=======================================================Analytic II====================================================================================================')

print(
df[['@timestamp','Hostname','Application','SourceAddress','DestAddress','LayerName','LayerRTID']]

[(df['Channel'].str.lower() == 'security')
    & (df['EventID'] == 5156)
    & (
        (df['DestPort'] == 5985)
        | (df['DestPort'] == 5986)
    )
    & (df['LayerRTID'] == 44)
]
.head()
)

#Analytic III
print('=======================================================Analytic III===================================================================================================')
print(
df[['@timestamp','Hostname','ParentProcessName','NewProcessName']]

[(df['Channel'].str.lower() == 'security')
    & (df['EventID'] == 4688)
    & (
        (df['ParentProcessName'].str.lower().str.endswith('wsmprovhost.exe', na=False))
        | (df['NewProcessName'].str.lower().str.endswith('wsmprovhost.exe', na=False))
    )
]
.head()
)
#Analytic IV
print('=======================================================Analytic IV====================================================================================================')
print(
df[['@timestamp','Hostname','ParentImage','Image']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 1)
    & (
        (df['ParentImage'].str.lower().str.endswith('wsmprovhost.exe', na=False))
        | (df['Image'].str.lower().str.endswith('wsmprovhost.exe', na=False))
    )
]
.head()
)
#Analytic V
print('=======================================================Analytic V=====================================================================================================')
print(
df[['@timestamp','Hostname','User','Initiated','Image','SourceIp','DestinationIp']]

[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 3)
    & (
        (df['DestinationPort'] == 5985)
        | (df['DestinationPort'] == 5986)
    )
    & (~df['User'].isin(['NT AUTHORITY\\NETWORK SERVICE', 'NT AUTHORITY\\SYSTEM']))
]
)