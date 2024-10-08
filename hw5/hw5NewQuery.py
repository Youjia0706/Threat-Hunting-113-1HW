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

# 1. 可疑的使用者行為分析
threshold = 5  # 設定登入次數的閾值
suspiciousLogins = df[
    (df['Channel'].str.lower() == 'security') &
    (df['EventID'] == 4624) &
    (df['LogonType'] == 3)
].groupby('SubjectUserName').filter(lambda x: len(x) > threshold)

print('=======================================================Suspicious Logins=======================================================================================')
print(suspiciousLogins[['@timestamp', 'Hostname', 'SubjectUserName', 'SubjectLogonId']])

# 2. 使用者與群組變更監控
userGroupChanges = df[
    (df['Channel'].str.lower() == 'security') &
    (df['EventID'].isin([4728, 4729]))  # 4728: 新增成員到群組，4729: 移除成員
]

print('=======================================================User and Group Changes=================================================================================')
print(userGroupChanges[['@timestamp', 'Hostname', 'SubjectUserName', 'EventID']])

# 3. 登錄失敗事件分析
failedLogins = df[
    (df['Channel'].str.lower() == 'security') &
    (df['EventID'] == 4625)  # 4625: 登錄失敗
].groupby('SubjectUserName').size().reset_index(name='Failed Login Count')

print('=======================================================Failed Logins=========================================================================================')
print(failedLogins)

# 4. 檢查特定 IP 地址的活動
suspiciousIp = '172.18.39.5'  # 假設要檢查的 IP 地址
activitiesFromIp = df[df['IpAddress'] == suspiciousIp]

print('=======================================================Activities from Specific IP===========================================================================')
print(activitiesFromIp[['@timestamp', 'Hostname', 'SubjectUserName', 'EventID']])

# 5. 登入類型分析
loginTypes = df[
    (df['Channel'].str.lower() == 'security') &
    (df['EventID'] == 4624)
].groupby('LogonType').size().reset_index(name='Login Count')
print('=======================================================Login Types===========================================================================================')
print(loginTypes)