import requests
from zipfile import ZipFile
from io import BytesIO
import pandas as pd
from pandas.io import json

#Download Dataset
url = 'https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/atomic/windows/credential_access/host/empire_mimikatz_logonpasswords.zip'
zipFileRequest = requests.get(url)
zipFile = ZipFile(BytesIO(zipFileRequest.content))
datasetJSONPath = zipFile.extract(zipFile.namelist()[0])

#Read Dataset
df = json.read_json(path_or_buf=datasetJSONPath, lines=True)

# Analytic I
analytic_I_df = df[['@timestamp','Hostname','SubjectUserName','ProcessName','ObjectName','AccessMask','EventID']][
    (df['Channel'].str.lower() == 'security') &
    ((df['EventID'] == 4663) | (df['EventID'] == 4656)) &
    (df['ObjectName'].str.contains('.*lsass.exe', regex=True)) &
    (~df['SubjectUserName'].str.endswith('.*$', na=False))
].head()

# Analytic II
analytic_II_df = df[['@timestamp','Hostname','SourceImage','TargetImage','GrantedAccess','SourceProcessGUID','CallTrace']][
    (df['Channel'] == 'Microsoft-Windows-Sysmon/Operational') &
    (df['EventID'] == 10) &
    (df['TargetImage'].str.contains('.*lsass.exe', regex=True)) &
    (df['CallTrace'].str.contains('.*UNKNOWN*', regex=True))
].head()

# Analytic III
analytic_III_df = df[['@timestamp','ProcessGuid','Image','ImageLoaded']][
    (df['Channel'] == 'Microsoft-Windows-Sysmon/Operational') &
    (df['EventID'] == 7) &
    (
        (df['ImageLoaded'].str.contains('.*samlib.dll', regex=True)) |
        (df['ImageLoaded'].str.contains('.*vaultcli.dll', regex=True)) |
        (df['ImageLoaded'].str.contains('.*hid.dll', regex=True)) |
        (df['ImageLoaded'].str.contains('.*winscard.dll', regex=True)) |
        (df['ImageLoaded'].str.contains('.*cryptdll.dll', regex=True))
    ) &
    (df['@timestamp'].between('2020-06-00 00:00:00.000','2020-08-20 00:00:00.000'))
].groupby(['ProcessGuid','Image'])['ImageLoaded'].count().sort_values(ascending=False).to_frame()

# Analytic IV
imageLoadDf = analytic_III_df
processAccessDf = df[['@timestamp', 'Hostname', 'SourceImage', 'TargetImage', 'GrantedAccess', 'SourceProcessGUID']][
    (df['Channel'] == 'Microsoft-Windows-Sysmon/Operational') &
    (df['EventID'] == 10) &
    (df['TargetImage'].str.contains('.*lsass.exe', regex=True)) &
    (df['CallTrace'].str.contains('.*UNKNOWN*', regex=True))
]

# Merging DataFrames
analytic_IV_df = pd.merge(imageLoadDf, processAccessDf, left_on='ProcessGuid', right_on='SourceProcessGUID', how='inner')

# Exporting to CSV
output_path = './analytic_results.csv'
analytic_I_df.to_csv(output_path, mode='w', index=False)
analytic_II_df.to_csv(output_path, mode='a', index=False)
analytic_III_df.to_csv(output_path, mode='a')
analytic_IV_df.to_csv(output_path, mode='a', index=False)

# Write the results to the CSV file with separators
with open(output_path, 'w') as f:
    # Write Analytic I with separator
    f.write('========================================Analytic I====================================================\n')
    analytic_I_df.to_csv(f, index=False)
    
    # Write Analytic II with separator
    f.write('\n========================================Analytic II====================================================\n')
    analytic_II_df.to_csv(f, index=False)
    
    # Write Analytic III with separator
    f.write('\n========================================Analytic III====================================================\n')
    analytic_III_df.to_csv(f)
    
    # Write Analytic IV with separator
    f.write('\n========================================Analytic IV====================================================\n')
    analytic_IV_df.to_csv(f, index=False)