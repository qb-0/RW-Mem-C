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
    kernel32 = ctypes.WinDLL('kernel32.dll')

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


    class ModuleEntry32(ctypes.Structure):
        _fields_ = [
            ('dwSize', ctypes.c_ulong),
            ('th32ModuleID', ctypes.c_ulong),
            ('th32ProcessID', ctypes.c_ulong),
            ('GlblcntUsage', ctypes.c_ulong),
            ('ProccntUsage', ctypes.c_ulong),
            ('modBaseAddr', ctypes.POINTER(ctypes.c_ulonglong)),
            ('modBaseSize', ctypes.c_ulong),
            ('hModule', ctypes.c_ulong),
            ('szModule', ctypes.c_char * 256),
            ('szExePath', ctypes.c_char * 260)
        ]


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

    Module32First = kernel32.Module32First
    Module32First.restype = ctypes.c_ulonglong
    Module32First.argtypes = [ctypes.c_void_p, ctypes.POINTER(ModuleEntry32)]

    Module32Next = kernel32.Module32Next
    Module32Next.restype = ctypes.c_ulonglong
    Module32Next.argtypes = [ctypes.c_void_p, ctypes.POINTER(ModuleEntry32)]
else:
    exit("Unsupported platform")

class Memory:
    def __init__(self, process):
        if isLin and os.getuid() != 0:
            raise OSError("Pymem requires root privileges")

        self.pid = process if isinstance(process, int) else self.get_pid(process)
        if isWin:
            self.handle = OpenProcess(0x1FFFFF, False, self.pid)
            print(self.handle)

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
            raise Exception("Module not found")
        elif isWin:
            hSnap = CreateToolhelp32Snapshot(0x18, self.pid)
            entry = ModuleEntry32()
            entry.dwSize = ctypes.sizeof(entry)
            result = Module32First(hSnap, ctypes.byref(entry))
            print(result)
            while result:
                print(hSnap.szModule)
                result = Module32Next(hSnap, ctypes.byref(entry))
            CloseHandle(hSnap)

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
            result = process_vm_writev(self.pid, ctypes.byref(io_src), 1, ctypes.byref(io_dst), 1, 0)
        if result == -1:
            raise OSError(ctypes.get_errno())
        return result

    def read_string(self, address, max_length=50):
        return self.read(address, (max_length * ctypes.c_char)()).decode()

    def write_string(self, address, string):
        buff = ctypes.create_string_buffer(string.encode())
        return self.write(address, buff)

    def read_array(self, address, c_type, length):
        return self.read(address, (c_type * length)(), False)[:]