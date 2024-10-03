import requests
from zipfile import ZipFile
from io import BytesIO
import pandas as pd
from pandas.io import json

#Download Dataset
url = ('https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic'
'/windows/credential_access/host/empire_mimikatz_logonpasswords.zip')
zipFileRequest = requests.get(url)
zipFile = ZipFile(BytesIO(zipFileRequest.content))
datasetJSONPath = zipFile.extract(zipFile.namelist()[0])

#Read Dataset
df = json.read_json(path_or_buf=datasetJSONPath, lines=True)

#Analytic I
print('========================================Analytic I====================================================')
print(
df[['@timestamp','Hostname','SubjectUserName','ProcessName','ObjectName','AccessMask','EventID']]
[(df['Channel'].str.lower() == 'security')
    & ((df['EventID'] == 4663) | (df['EventID'] == 4656))
    & (df['ObjectName'].str.contains('.*lsass.exe', regex=True))
    & (~df['SubjectUserName'].str.endswith('.*$', na=False))
]
.head()
)

#Analytic II
print('========================================Analytic II====================================================')
print(
df[['@timestamp','Hostname','SourceImage','TargetImage','GrantedAccess','SourceProcessGUID','CallTrace']]
[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 10)
    & (df['TargetImage'].str.contains('.*lsass.exe', regex=True))
    & (df['CallTrace'].str.contains('.*UNKNOWN*', regex=True))
]
.head()
)

#Analytic III
print('========================================Analytic III====================================================')
print(
df[['@timestamp','ProcessGuid','Image','ImageLoaded']]
[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 7)
    & (
        (df['ImageLoaded'].str.contains('.*samlib.dll', regex=True))
        | (df['ImageLoaded'].str.contains('.*vaultcli.dll', regex=True))
        | (df['ImageLoaded'].str.contains('.*hid.dll', regex=True))
        | (df['ImageLoaded'].str.contains('.*winscard.dll', regex=True))
        | (df['ImageLoaded'].str.contains('.*cryptdll.dll', regex=True))
    )
    & (df['@timestamp'].between('2020-06-00 00:00:00.000','2020-08-20 00:00:00.000'))
]
.groupby(['ProcessGuid','Image'])['ImageLoaded'].count().sort_values(ascending=False)
.to_frame())

#Analytic IV
print('========================================Analytic IV====================================================')
imageLoadDf = (
df[['@timestamp','ProcessGuid','Image','ImageLoaded']]
[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 7)
    & (
        (df['ImageLoaded'].str.contains('.*samlib.dll', regex=True))
        | (df['ImageLoaded'].str.contains('.*vaultcli.dll', regex=True))
        | (df['ImageLoaded'].str.contains('.*hid.dll', regex=True))
        | (df['ImageLoaded'].str.contains('.*winscard.dll', regex=True))
        | (df['ImageLoaded'].str.contains('.*cryptdll.dll', regex=True))
    )
    & (df['@timestamp'].between('2020-06-00 00:00:00.000','2020-08-20 00:00:00.000'))
]
.groupby(['ProcessGuid','Image'])['ImageLoaded'].count().sort_values(ascending=False)
).to_frame()

processAccessDf = (
df[['@timestamp', 'Hostname', 'SourceImage', 'TargetImage', 'GrantedAccess', 'SourceProcessGUID']]
[(df['Channel'] == 'Microsoft-Windows-Sysmon/Operational')
    & (df['EventID'] == 10)
    & (df['TargetImage'].str.contains('.*lsass.exe', regex=True))
    & (df['CallTrace'].str.contains('.*UNKNOWN*', regex=True))
]
)
print(
pd.merge(imageLoadDf, processAccessDf,
    left_on = 'ProcessGuid', right_on = 'SourceProcessGUID', how = 'inner')
)