import memory
from ctypes import *

class Test(Structure):
    _fields_ = [
        ("x", c_float),
        ("y", c_byte)
    ]

print(memory.read_mem(17899, 0x024AD224, c_int32()))
print(memory.read_mem(17899, 0x03C4E408, c_float()))
a = create_string_buffer(5)
print(memory.read_mem(17899, 0x023539F0, a))
my_struct = memory.read_mem(17899, 0x03C4E408, Test(), False)
print(my_struct.x, my_struct.y)

memory.write_mem(17899, 0x024AD224, c_int32(127368))
print(memory.read_mem(17899, 0x024AD224, c_int32()))