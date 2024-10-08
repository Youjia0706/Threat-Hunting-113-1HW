# Active Directory Object Access via Replication Services
import requests
from zipfile import ZipFile
from io import BytesIO
import pandas as pd
from pandas.io import json

# Download Dataset
url = ('https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/'
       'windows/credential_access/host/empire_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip')
zipFileRequest = requests.get(url)
zipFile = ZipFile(BytesIO(zipFileRequest.content))
datasetJSONPath = zipFile.extract(zipFile.namelist()[0])
# Read Dataset
df = json.read_json(path_or_buf=datasetJSONPath, lines=True)

# Analytic I
print('=======================================================Analytic I=========================================================================================')
print(
df[['@timestamp','Hostname','SubjectUserName','SubjectLogonId']]

[(df['Channel'].str.lower() == 'security')
    & (df['EventID'] == 4662)
    & (df['AccessMask'] == '0x100')
    & (
        (df['Properties'].str.contains('.*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2.*', regex=True))
        | (df['Properties'].str.contains('.*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2.*', regex=True))
        | (df['Properties'].str.contains('.*89e95b76-444d-4c62-991a-0facbeda640c.*', regex=True))
    )
    & (~df['SubjectUserName'].str.endswith('.*$', na=False))
]
)

# Analytic II
print('=======================================================Analytic II=========================================================================================')
adObjectAccessDf = (
df[['@timestamp','Hostname','SubjectUserName','SubjectLogonId']]

[(df['Channel'].str.lower() == 'security')
    & (df['EventID'] == 4662)
    & (df['AccessMask'] == '0x100')
    & (
        (df['Properties'].str.contains('.*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2.*', regex=True))
        | (df['Properties'].str.contains('.*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2.*', regex=True))
        | (df['Properties'].str.contains('.*89e95b76-444d-4c62-991a-0facbeda640c.*', regex=True))
    )
    & (~df['SubjectUserName'].str.endswith('.*$', na=False))
]
)

networkLogonDf = (
df[['@timestamp','Hostname','TargetUserName','TargetLogonId','IpAddress']]

[(df['Channel'].str.lower() == 'security')
    & (df['EventID'] == 4624)
    & (df['LogonType'] == 3)
    & (~df['SubjectUserName'].str.endswith('.*$', na=False))
]
)

print(
pd.merge(adObjectAccessDf, networkLogonDf,
    left_on = 'SubjectLogonId', right_on = 'TargetLogonId', how = 'inner')
)