import os
import ctypes

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


class Mem:
    def __init__(self, process):
        if os.getuid() != 0:
            raise OSError("Pymem requires root privileges")

        self.pid = process if isinstance(process, int) else self.get_pid(process)

    def get_pid(self, process_name):
        for pid in [p for p in os.listdir("/proc") if p.isdigit()]:
            if open(f"/proc/{pid}/comm").read().strip() == process_name:
                return int(pid)
        raise Exception("Process not found")

    def module_base(self, name):
        for l in open(f"/proc/{self.pid}/maps"):
            if name in l:
                return int("0x" + l.split("-")[0], 0)
        raise Exception("Module not found")

    def read_mem(self, address, c_type, get_py_value=True):
        if not isinstance(address, int):
            raise TypeError("Address must be int: {}".format(address))

        size = ctypes.sizeof(c_type)
        buff = ctypes.create_string_buffer(size)
        io_dst = IOVec(ctypes.cast(ctypes.byref(buff), ctypes.c_void_p), size)
        io_src = IOVec(ctypes.c_void_p(address), size)
        if process_vm_readv(self.pid, ctypes.byref(io_dst), 1, ctypes.byref(io_src), 1, 0) == -1:
            raise OSError(ctypes.get_errno())
        ctypes.memmove(ctypes.byref(c_type), ctypes.byref(buff), size)
        if get_py_value:
            return c_type.value
        return c_type

    def write_mem(self, address, data):
        if not isinstance(address, int):
            raise TypeError("Address must be int: {}".format(address))

        size = ctypes.sizeof(data)
        buff = ctypes.create_string_buffer(size)
        ctypes.memmove(ctypes.byref(buff), ctypes.byref(data), size)
        io_src = IOVec(ctypes.cast(ctypes.byref(buff), ctypes.c_void_p), size)
        io_dst = IOVec(ctypes.c_void_p(address), size)
        result = process_vm_writev(self.pid, ctypes.byref(io_src), 1, ctypes.byref(io_dst), 1, 0)
        if result == -1:
            raise OSError(ctypes.get_errno())
        return result

    def read_string(self, address, max_length=50):
        return self.read_mem(address, (max_length * ctypes.c_char)()).decode()

    def write_string(self, address, string):
        buff = ctypes.create_string_buffer(string.encode())
        return self.write_mem(address, buff)

    def read_array(self, address, c_type, length):
        return self.read_mem(address, (c_type * length)(), False)[:]