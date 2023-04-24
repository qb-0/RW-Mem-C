import sys
import os
import ctypes

from typing import Union, Any, Iterator, NamedTuple
from collections import namedtuple

isLin = sys.platform == "linux"
isWin = sys.platform == "win32"

if isLin:
    class IOVec(ctypes.Structure):
        _fields_ = [
            ("iov_base", ctypes.c_void_p),
            ("iov_len", ctypes.c_size_t)
        ]


    libc = ctypes.CDLL("libc.so.6")

    process_vm_readv = libc.process_vm_readv
    process_vm_readv.argtypes = [
        ctypes.c_int, 
        ctypes.POINTER(IOVec), 
        ctypes.c_ulong, 
        ctypes.POINTER(IOVec), 
        ctypes.c_ulong, 
        ctypes.c_ulong
    ]
    process_vm_readv.restype = ctypes.c_ssize_t

    process_vm_writev = libc.process_vm_writev
    process_vm_writev.argtypes = [
        ctypes.c_int, 
        ctypes.POINTER(IOVec), 
        ctypes.c_ulong, 
        ctypes.POINTER(IOVec), 
        ctypes.c_ulong, 
        ctypes.c_ulong
    ]
    process_vm_writev.restype = ctypes.c_ssize_t
elif isWin:
    class ProcessEntry32(ctypes.Structure):
        _fields_ = [
            ('dwSize', ctypes.c_ulong),
            ('cntUsage', ctypes.c_ulong),
            ('th32ProcessID', ctypes.c_ulong),
            ('th32DefaultHeapID', ctypes.POINTER(ctypes.c_ulong)),
            ('th32ModuleID', ctypes.c_ulong),
            ('cntThreads', ctypes.c_ulong),
            ('th32ParentProcessID', ctypes.c_ulong),
            ('pcPriClassBase', ctypes.c_ulong),
            ('dwFlags', ctypes.c_ulong),
            ('szExeFile', ctypes.c_char * 260)
        ]


    class MODULEINFO(ctypes.Structure):
        _fields_ = [
            ("lpBaseOfDll", ctypes.c_void_p),
            ("SizeOfImage", ctypes.c_ulong),
            ("EntryPoint", ctypes.c_void_p),
        ]


    kernel32 = ctypes.WinDLL("kernel32.dll")
    psapi = ctypes.WinDLL("psapi.dll")

    GetLastError = kernel32.GetLastError
    GetLastError.restype = ctypes.c_ulong

    OpenProcess = kernel32.OpenProcess
    OpenProcess.restype = ctypes.c_void_p

    CloseHandle = kernel32.CloseHandle
    CloseHandle.restype = ctypes.c_long
    CloseHandle.argtypes = [ctypes.c_void_p]

    CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
    CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]

    Process32First = kernel32.Process32First
    Process32First.argtypes = [ctypes.c_void_p , ctypes.POINTER(ProcessEntry32)]
    Process32First.restype = ctypes.c_long

    Process32Next = kernel32.Process32Next
    Process32Next.argtypes = [ctypes.c_void_p , ctypes.POINTER(ProcessEntry32)]
    Process32Next.restype = ctypes.c_long

    EnumProcessModulesEx = psapi.EnumProcessModulesEx
    EnumProcessModulesEx.restype = ctypes.c_bool

    GetModuleInformation = psapi.GetModuleInformation
    GetModuleInformation.restype = ctypes.c_bool

    GetModuleBaseNameA = psapi.GetModuleBaseNameA
    GetModuleBaseNameA.restype = ctypes.c_ulonglong

    ReadProcessMemory = kernel32.ReadProcessMemory
    ReadProcessMemory.argtypes = (
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t)
    )
    ReadProcessMemory.restype = ctypes.c_long

    WriteProcessMemory = kernel32.WriteProcessMemory
    WriteProcessMemory.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t)
    ]
    WriteProcessMemory.restype = ctypes.c_long
else:
    exit("Unsupported platform")


class Memory:
    def __init__(self, process: Union[str, int]) -> None:
        self.proc_buf = namedtuple("Process", "name pid")

        if isLin and os.getuid() != 0:
            raise OSError("Pymem requires root privileges")

        if isinstance(process, int):
            if self.pid_exists(process):
                self.pid = process if isinstance(process, int) else self.get_pid(process)
            else:
                raise Exception(f"Process ID '{process}' does not exist")
        else:
            self.pid = self.get_pid(process)

        if isWin:
            self.handle = OpenProcess(0x1FFFFF, False, self.pid)

    @property
    def name(self):
        for proc in self.enum_processes():
            if proc.pid == self.pid:
                return proc.name
    
    @property
    def base(self):
        return self.module_base(self.name)

    def enum_processes(self) -> Iterator[NamedTuple]:
        if isLin:
            for pid in [p for p in os.listdir("/proc") if p.isdigit()]:
                self.proc_buf.name = open(f"/proc/{pid}/comm").read().strip()
                self.proc_buf.pid = int(pid)
                yield self.proc_buf
        elif isWin:
            snap = CreateToolhelp32Snapshot(0x2, 0)
            entry = ProcessEntry32()
            entry.dwSize = ctypes.sizeof(entry)
            result = Process32First(snap, ctypes.byref(entry))
            while result:
                self.proc_buf.name = entry.szExeFile.decode()
                self.proc_buf.pid = entry.th32ProcessID
                yield self.proc_buf
                result = Process32Next(snap, ctypes.byref(entry))
            CloseHandle(snap)

    def pid_exists(self, pid: int) -> bool:
        return pid in [p.pid for p in self.enum_processes()]

    def get_pid(self, process_name: str) -> int:
        for proc in self.enum_processes():
            if proc.name == process_name:
                return proc.pid
        raise Exception(f"Process '{process_name}' not found")
    
    def get_name(self, pid: int) -> str:
        for proc in self.enum_processes():
            if proc.pid == pid:
                return proc.name

    def module_base(self, name: str) -> int:
        if isLin:
            for l in open(f"/proc/{self.pid}/maps"):
                if name.lower() in l.lower():
                    return int("0x" + l.split("-")[0], 0)
        elif isWin:
            modules = (ctypes.c_void_p * 1024)()
            EnumProcessModulesEx(
                self.handle,
                ctypes.byref(modules),
                ctypes.sizeof(modules),
                ctypes.byref(ctypes.c_ulong()),
                0x03
            )
            module_info = MODULEINFO()
            for m in modules:
                GetModuleInformation(
                    self.handle,
                    ctypes.c_void_p(m),
                    ctypes.byref(module_info),
                    ctypes.sizeof(module_info)
                )
                if module_info.lpBaseOfDll:
                    modname = ctypes.c_buffer(260)
                    GetModuleBaseNameA(
                        self.handle,
                        ctypes.c_void_p(module_info.lpBaseOfDll),
                        modname,
                        ctypes.sizeof(modname)
                    )
                    if modname.value.decode().lower() == name.lower():
                        return module_info.lpBaseOfDll
        
        raise Exception(f"Module '{name}' not found")

    def read(self, address: int, c_type, get_py_value=True) -> Any:
        size = ctypes.sizeof(c_type)
        buff = ctypes.create_string_buffer(size)
        if isLin:
            io_dst = IOVec(ctypes.cast(ctypes.byref(buff), ctypes.c_void_p), size)
            io_src = IOVec(ctypes.c_void_p(address), size)
            if process_vm_readv(self.pid, ctypes.byref(io_dst), 1, ctypes.byref(io_src), 1, 0) == -1:
                raise OSError(ctypes.get_errno())
        elif isWin:
            if ReadProcessMemory(self.handle, ctypes.c_void_p(address), ctypes.byref(buff), size, None) == 0:
                raise OSError(GetLastError())
        ctypes.memmove(ctypes.byref(c_type), ctypes.byref(buff), size)
        if get_py_value:
            return c_type.value
        return c_type

    def write(self, address: int, data: Any) -> int:
        size = ctypes.sizeof(data)
        buff = ctypes.create_string_buffer(size)
        ctypes.memmove(ctypes.byref(buff), ctypes.byref(data), size)
        if isLin:
            io_src = IOVec(ctypes.cast(ctypes.byref(buff), ctypes.c_void_p), size)
            io_dst = IOVec(ctypes.c_void_p(address), size)
            result = process_vm_writev(self.pid, ctypes.byref(io_src), 1, ctypes.byref(io_dst), 1, 0)
            if result == -1:
                raise OSError(ctypes.get_errno())
            return result
        elif isWin:
            dst = ctypes.cast(address, ctypes.c_char_p)
            result = ctypes.c_size_t()
            if WriteProcessMemory(self.handle, dst, buff, size, ctypes.byref(result)) == 0:
                raise OSError(GetLastError())
            return result

    def read_string(self, address: int, max_length: int = 50) -> str:
        return self.read(address, (max_length * ctypes.c_char)()).decode()

    def write_string(self, address: int, string: str):
        buff = ctypes.create_string_buffer(string.encode())
        return self.write(address, buff)

    def read_array(self, address: int, c_type, length: int) -> list:
        return self.read(address, (c_type * length)(), False)[:]

    def get_error(self) -> int:
        if isLin:
            return ctypes.get_errno()
        elif isWin:
            return GetLastError()

    def close(self) -> bool:
        if isWin:
            return CloseHandle(self.handle) != 0