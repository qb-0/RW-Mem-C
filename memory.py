import sys
import os
import ctypes

isLin = sys.platform == "linux"
isWin = sys.platform == "win32"

if isLin:
    libc = ctypes.CDLL("libc.so.6")

    class IOVec(ctypes.Structure):
        _fields_ = [
            ("iov_base", ctypes.c_void_p),
            ("iov_len", ctypes.c_size_t)
        ]


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
    kernel32 = ctypes.WinDLL("kernel32.dll")
    psapi = ctypes.WinDLL("psapi.dll")

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
    def __init__(self, process):
        if isLin and os.getuid() != 0:
            raise OSError("Pymem requires root privileges")

        self.pid = process if isinstance(process, int) else self.get_pid(process)
        if isWin:
            self.handle = OpenProcess(0x1FFFFF, False, self.pid)

    def get_pid(self, process_name):
        if isLin:
            for pid in [p for p in os.listdir("/proc") if p.isdigit()]:
                if open(f"/proc/{pid}/comm").read().strip() == process_name:
                    return int(pid)
        elif isWin:
            hSnap = CreateToolhelp32Snapshot(0x2, 0)
            entry = ProcessEntry32()
            entry.dwSize = ctypes.sizeof(entry)
            result = Process32First(hSnap, ctypes.byref(entry))
            while result:
                if entry.szExeFile.decode() == process_name:
                    CloseHandle(hSnap)
                    return entry.th32ProcessID
                result = Process32Next(hSnap, ctypes.byref(entry))
            CloseHandle(hSnap)

        raise Exception("Process not found")

    def module_base(self, name):
        if isLin:
            for l in open(f"/proc/{self.pid}/maps"):
                if name in l:
                    return int("0x" + l.split("-")[0], 0)
        elif isWin:
            module_info = MODULEINFO()
            hModules = (ctypes.c_void_p * 1024)()
            EnumProcessModulesEx(
                self.handle,
                ctypes.byref(hModules),
                ctypes.sizeof(hModules),
                ctypes.byref(ctypes.c_ulong()),
                0x03
            )
            for m in hModules:
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
                    if modname.value.decode() == name:
                        return module_info.lpBaseOfDll
        
        raise Exception(f"Module '{name}' not found")

    def read(self, address, c_type, get_py_value=True):
        if not isinstance(address, int):
            raise TypeError("Address must be int: {}".format(address))

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

    def write(self, address, data):
        if not isinstance(address, int):
            raise TypeError("Address must be int: {}".format(address))

        size = ctypes.sizeof(data)
        buff = ctypes.create_string_buffer(size)
        ctypes.memmove(ctypes.byref(buff), ctypes.byref(data), size)
        if isLin:
            io_src = IOVec(ctypes.cast(ctypes.byref(buff), ctypes.c_void_p), size)
            io_dst = IOVec(ctypes.c_void_p(address), size)
            if process_vm_writev(self.pid, ctypes.byref(io_src), 1, ctypes.byref(io_dst), 1, 0) == -1:
                raise OSError(ctypes.get_errno())
        elif isWin:
            dst = ctypes.cast(address, ctypes.c_char_p)
            if WriteProcessMemory(self.handle, dst, buff, size, None) == 0:
                raise OSError(GetLastError())

    def read_string(self, address, max_length=50):
        return self.read(address, (max_length * ctypes.c_char)()).decode()

    def write_string(self, address, string):
        buff = ctypes.create_string_buffer(string.encode())
        return self.write(address, buff)

    def read_array(self, address, c_type, length):
        return self.read(address, (c_type * length)(), False)[:]

    def get_error(self):
        if isLin:
            return ctypes.get_errno()
        elif isWin:
            return GetLastError()

    def close(self):
        if isWin:
            return CloseHandle(self.handle)