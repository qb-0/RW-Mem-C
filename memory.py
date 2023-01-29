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

def read_mem(pid, address, c_type, get_py_value=True):
    if not isinstance(address, int):
        raise TypeError("Address must be int: {}".format(address))

    size = ctypes.sizeof(c_type)
    buff = ctypes.create_string_buffer(size)
    io_dst = IOVec(ctypes.cast(ctypes.byref(buff), ctypes.c_void_p), size)
    io_src = IOVec(ctypes.c_void_p(address), size)
    if process_vm_readv(pid, ctypes.byref(io_dst), 1, ctypes.byref(io_src), 1, 0) == -1:
        raise OSError(ctypes.get_errno())
    ctypes.memmove(ctypes.byref(c_type), ctypes.byref(buff), size)
    if get_py_value:
        return c_type.value
    return c_type

def write_mem(pid, address, data):
    if not isinstance(address, int):
        raise TypeError("Address must be int: {}".format(address))

    size = ctypes.sizeof(data)
    buff = ctypes.create_string_buffer(size)
    ctypes.memmove(ctypes.byref(buff), ctypes.byref(data), size)
    io_src = IOVec(ctypes.cast(ctypes.byref(buff), ctypes.c_void_p), size)
    io_dst = IOVec(ctypes.c_void_p(address), size)
    result = process_vm_writev(pid, ctypes.byref(io_src), 1, ctypes.byref(io_dst), 1, 0)
    if result == -1:
        raise OSError(ctypes.get_errno())
    return result