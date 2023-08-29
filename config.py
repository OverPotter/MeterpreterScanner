WIN_7_SIGNATURE = ["WINBRAND.dll", "WINHTTP.dll", "webio.dll", "SspiCli.dll", "cscapi.dll"]
WIN_10_SIGNATURE = ["rsaenh.dll", "netapi32.dll", "wkscli.dll", "psapi.dll", "cscapi.dll"]

REG_FOR_WINDOWS_VERSION = r'(?:Windows\s+)(\d+|XP|\d+\.\d+)'
REG_FOR_EXE_PROCESSES = r'(?<=\\r\\n)[A-Za-z]+\.exe\s+\d+'
REG_FOR_LOCAL_SOCKET = r'(?:TCP\s+)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5})'
REG_FOR_REMOTE_SOCKET = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5})\s+[A-Z]+\s+(\d+)'

# check established connection
CMD_NETSTAT_COMMAND = 'netstat -aon |find /i "established"'
# show all process with their dll
CMD_TASKLIST_COMMAND = "tasklist /M"
