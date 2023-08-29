import re
import subprocess

from typing import List, Dict
from config import *


class MeterpreterScaner:
    def __init__(self):
        self._signatures: List[str] = []
        self._processes_with_signatures: List[str] = []
        self._processes_with_dynamic_port: List[str] = []
        self._suspicious_processes: Dict[str:List[str]] = {}

    def _check_windows_version(self) -> None:
        info = subprocess.check_output("systeminfo", shell=True)
        win = re.findall(REG_FOR_WINDOWS_VERSION, str(info))

        if win[0] == '10':
            self._signatures = WIN_10_SIGNATURE
        elif win[0] == '7':
            self._signatures = WIN_7_SIGNATURE
        else:
            print("[X] Only for Windows 7 or Windows 10.")

    # function for search dll used by the process
    def _search_process_with_dll(self, dll: str) -> None:
        output_tasklist = subprocess.check_output(f"{CMD_TASKLIST_COMMAND} {dll}", shell=True)
        process_list = re.findall(REG_FOR_EXE_PROCESSES, str(output_tasklist))

        for process_info in process_list:
            process, process_PID = re.split(r'\s+', process_info)
            if process in self._suspicious_processes:
                self._suspicious_processes[f'{process}_{process_PID}'].append(dll)
            else:
                self._suspicious_processes[f'{process}_{process_PID}'] = [dll]

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


if __name__ == '__main__':
    MeterpreterScaner().finding_meterpreter_sessions()
