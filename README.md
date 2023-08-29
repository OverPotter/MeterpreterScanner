# Обнаружение meterpreter сессий в ОС Windows

### Анализ

Постараюсь изложить все доступно и компакно не углубляюсь во всю работу. Для начала я решил создать n-е колличество полезныз нагрузок (windows/meterpreter/reverse_tcp, shell/bind_tcp, shell_hidden_bind_tcp, vncinject/reverse_tcp, cmd/windows/reverse_powershell), чтобы проанализировать, что будет происходить в системе посли их инъекции.

- Полезные нагрузки shell/bind_tcp и shell_hidden_bind_tcp, в качестве соединения используют bind соединение, то есть мы можем увидеть, как злоумышленник подключается к нашим портам, данные полезные нагрузки не относятся к meterpreter и не могут мигрировать между процессами и при нахождении в системе не подгружают специфичные dll в систему.
- Полезная нагрузка vncinject/reverse_tcp так же не использует специфичные dll, но при установке соединения начинает транслировать трафик через браузер по порту, относящемуся к VNC протоколу [(порты 5900+N и 5900+ N)](https://en.wikipedia.org/wiki/Virtual_Network_Computing#cite_note-6).
- А вот полезные нагрузки имеющие реверсный тип соединения windows/meterpreter/reverse_tcp и cmd/windows/reverse_powershell как во время запуска, как и после миграций подгружали за собой свои dll. Ну и конечно же открывали порты.

Таким образом я смогу получить список dll которые характерны этим полезным нагрузкам:

```python
WIN_7_SIGNATURE = ["WINBRAND.dll", "WINHTTP.dll", "webio.dll", "SspiCli.dll", "cscapi.dll"]
WIN_10_SIGNATURE = ["rsaenh.dll", "netapi32.dll", "wkscli.dll", "psapi.dll", "cscapi.dll"]
```

### Разработка

Ну и после этого я решил накидать простенький скрипт, давайие рассмотрим его основные методы.

```python
class MeterpreterScaner:
    def __init__(self):
        self._signatures: List[str] = []
        self._processes_with_signatures: List[str] = []
        self._processes_with_dynamic_port: List[str] = []
        self._suspicious_processes: Dict[str:List[str]] = {}
```
Объявляем класс MeterpreterScaner и его переменные которые понадобятся нам в методах.

```python
def _check_windows_version(self) -> None:
    info = subprocess.check_output("systeminfo", shell=True)
    win = re.findall(REG_FOR_WINDOWS_VERSION, str(info))

    if win[0] == '10':
        self._signatures = WIN_10_SIGNATURE
    elif win[0] == '7':
        self._signatures = WIN_7_SIGNATURE
    else:
        print("[X] Only for Windows 7 or Windows 10.")
```
Метод позволяющий нам определить версию ОС (я тестировал только на семерке и десятке). Получаем информацию о системе и достаем из нее только версию с помощью регулярного вырожения. `REG_FOR_WINDOWS_VERSION = r'(?:Windows\s+)(\d+|XP|\d+\.\d+)'`

```python
def _search_process_with_dll(self, dll: str) -> None:
    output_tasklist = subprocess.check_output(f"{CMD_TASKLIST_COMMAND} {dll}", shell=True)
    process_list = re.findall(REG_FOR_EXE_PROCESSES, str(output_tasklist))

    for process_info in process_list:
        process, process_PID = re.split(r'\s+', process_info)
        if process in self._suspicious_processes:
            self._suspicious_processes[f'{process}_{process_PID}'].append(dll)
        else:
            self._suspicious_processes[f'{process}_{process_PID}'] = [dll]
```
Сначала получаем список всех процессов с интересующей нас dll с помощью команды `CMD_TASKLIST_COMMAND = "tasklist /M dll"`. Находим все запущенные .exe файлы `REG_FOR_EXE_PROCESSES = r'(?<=\\r\\n)[A-Za-z]+\.exe\s+\d+'` и заполняем наш словарь ими вместе с их PID процессов.

```python
def _check_suspicious_process(self) -> None:
    self._check_windows_version()

    for dll in self._signatures:
        self._search_process_with_dll(dll)
    for proc_info in self._suspicious_processes.items():
        proc_name, proc_dlls = proc_info
        if len(proc_dlls) == 5:
            print(f"[-] Detected meterpreter signature in memory: {proc_name}")
            self._processes_with_signatures.append(proc_name)
    if not self._processes_with_signatures:
        print("[+] Meterpreter signature in memory not found")
```
Тут мы проверяем полученные ранее процессы на количество dll из наших сигнатур.

```python
def _scan_suspicious_ports(self) -> None:
    scan_output = subprocess.check_output(CMD_NETSTAT_COMMAND, shell=True)
    local_sockets = re.findall(REG_FOR_LOCAL_SOCKET, str(scan_output))
    for l_socket in local_sockets:
        l_ip, l_port = l_socket.split(':')
        if int(l_port) >= 49152:
            if l_ip != "127.0.0.1":
                victim_socket = f"{l_ip}:{l_port}"
                data_with_suspicious_socket = scan_output.decode().split(victim_socket)
                suspicious_info = re.findall(REG_FOR_REMOTE_SOCKET, data_with_suspicious_socket[1])[0]
                suspicious_socket, suspicious_PID = suspicious_info
                # port 4444 used by default in MSF and meterpreter
                if int(suspicious_socket.split(':')[-1]) == 4444:
                    print(f"[!] Detected MSF connection with {suspicious_socket}")
                print(f"[-] Connection {victim_socket} to {suspicious_socket} "
                      f"used dynamic port on PID - {suspicious_PID}")
                self._processes_with_dynamic_port.append(suspicious_PID)
```
Смотрим открытые соединения командой `CMD_NETSTAT_COMMAND = 'netstat -aon |find /i "established"'`, фильтруем полученную информацию `REG_FOR_LOCAL_SOCKET = r'(?:TCP\s+)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5})'` и далее проверяем сокеты. Проверяем динамические порты и смотрим чтоб был не localhost. Если все совпадает получаем данные о remote soket `REG_FOR_REMOTE_SOCKET = r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5})\s+[A-Z]+\s+(\d+)'` и анализируем его. Если порт 4444 то это 99.(9)% что это полезная нагрузка ибо этот порт исполузется в MSF по умолчанию.
Также можно было добавить проверку на VNC, но думаю вы сможите добавить одно условие =)

```python
def finding_meterpreter_sessions(self):
    found = False
    self._check_suspicious_process()
    self._scan_suspicious_ports()

    for proc in self._processes_with_signatures:
        proc_name, proc_PID = proc.split('_')
        if proc_PID in self._processes_with_dynamic_port:
            print(f'[!] A match was found in process {proc_name} with PID {proc_PID}')
            found = True

    if not found:
        print(f"[+] A match wasn't found")
```
Ну и в конце метод который запускает весь этот скрипт.

### Заключение

В этой статье я постарался описать способ обнаружения реверсных полезных нагрузок meterpreter. Также я проводил анализ скриптов, которые я смог найти и написал скрипт для обнаружения meterpreter в дампе памяти, если вам будет интересно, могу написать об этом в следующий раз. Также если вы знаете другие сигнатуры или методы обнаружения напишите о них в комментарях.
