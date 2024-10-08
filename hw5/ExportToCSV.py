import requests
from zipfile import ZipFile
from io import BytesIO
import pandas as pd
from pandas.io import json

# Active Directory Object Access via Replication Services
# Download Dataset
url = 'https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/empire_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip'
zipFileRequest = requests.get(url)
zipFile = ZipFile(BytesIO(zipFileRequest.content))
datasetJSONPath = zipFile.extract(zipFile.namelist()[0])

# Read Dataset
df = json.read_json(path_or_buf=datasetJSONPath, lines=True)

# Initialize an Excel writer
excel_file = 'AD_Analysis_Results.xlsx'
with pd.ExcelWriter(excel_file) as writer:
    # Analytic I
    analytic_I = df[['@timestamp', 'Hostname', 'SubjectUserName', 'SubjectLogonId']][
        (df['Channel'].str.lower() == 'security') &
        (df['EventID'] == 4662) &
        (df['AccessMask'] == '0x100') &
        (
            (df['Properties'].str.contains('.*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2.*', regex=True)) |
            (df['Properties'].str.contains('.*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2.*', regex=True)) |
            (df['Properties'].str.contains('.*89e95b76-444d-4c62-991a-0facbeda640c.*', regex=True))
        ) &
        (~df['SubjectUserName'].str.endswith('.*$', na=False))
    ]
    # Write Analytic I results to Excel
    analytic_I.to_excel(writer, sheet_name='Analytic I', index=False)
    # Analytic II
    adObjectAccessDf = analytic_I
    networkLogonDf = df[['@timestamp', 'Hostname', 'TargetUserName', 'TargetLogonId', 'IpAddress']][
        (df['Channel'].str.lower() == 'security') &
        (df['EventID'] == 4624) &
        (df['LogonType'] == 3) &
        (~df['SubjectUserName'].str.endswith('.*$', na=False))
    ]
    analytic_II = pd.merge(adObjectAccessDf, networkLogonDf,
                            left_on='SubjectLogonId', right_on='TargetLogonId', how='inner')
    # Write Analytic II results to Excel
    analytic_II.to_excel(writer, sheet_name='Analytic II', index=False)

    # 1. 可疑的使用者行為分析
    threshold = 5  # 設定登入次數的閾值
    suspiciousLogins = df[
        (df['Channel'].str.lower() == 'security') &
        (df['EventID'] == 4624) &
        (df['LogonType'] == 3)
    ].groupby('SubjectUserName').filter(lambda x: len(x) > threshold)

    suspiciousLogins = suspiciousLogins[['@timestamp', 'Hostname', 'SubjectUserName', 'SubjectLogonId']]
    suspiciousLogins.to_excel(writer, sheet_name='Suspicious Logins', index=False)

    # 2. 使用者與群組變更監控
    userGroupChanges = df[
        (df['Channel'].str.lower() == 'security') &
        (df['EventID'].isin([4728, 4729]))  # 4728: 新增成員到群組，4729: 移除成員
    ]

    userGroupChanges = userGroupChanges[['@timestamp', 'Hostname', 'SubjectUserName', 'EventID']]
    userGroupChanges.to_excel(writer, sheet_name='User and Group Changes', index=False)

    # 3. 登錄失敗事件分析
    failedLogins = df[
        (df['Channel'].str.lower() == 'security') &
        (df['EventID'] == 4625)  # 4625: 登錄失敗
    ].groupby('SubjectUserName').size().reset_index(name='Failed Login Count')

    failedLogins.to_excel(writer, sheet_name='Failed Logins', index=False)

    # 4. 檢查特定 IP 地址的活動
    suspiciousIp = '172.18.39.5'  # 假設要檢查的 IP 地址
    activitiesFromIp = df[df['IpAddress'] == suspiciousIp]

    activitiesFromIp = activitiesFromIp[['@timestamp', 'Hostname', 'SubjectUserName', 'EventID']]
    activitiesFromIp.to_excel(writer, sheet_name='Activities from Specific IP', index=False)

    # 5. 登入類型分析
    loginTypes = df[
        (df['Channel'].str.lower() == 'security') &
        (df['EventID'] == 4624)
    ].groupby('LogonType').size().reset_index(name='Login Count')

    loginTypes.to_excel(writer, sheet_name='Login Types', index=False)

print(f'Analysis results have been saved to {excel_file}')