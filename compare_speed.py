import memory
import pymem
from time import time
from ctypes import *


class Addr:
    local_player = 0x18AC00
    name = 0x205
    health = 0xEC
    pos = 0x4


class LocalPlayer:
    def __init__(self) -> None:
        self.name = str()
        self.health = int()
        self.pos_x = float()
        self.pos_y = float()
        self.pos_z = float()


class LocalStruct(Structure):
    _fields_ = [
        ("", 0x4 * c_byte),
        ("pos_x", c_float),
        ("pos_y", c_float),
        ("pos_z", c_float),
        ("", 0xDC * c_byte),
        ("health", c_int),
        ("", 0x115 * c_byte),
        ("name", 0x50 * c_char),
    ]


def measure_pymem(n):
    local_player = LocalPlayer()
    proc = pymem.Pymem("ac_client.exe")
    base = proc.base_address
    local = proc.read_int(base + Addr.local_player)
    t_start = time()
    for _ in range(n):
        local_player.name = proc.read_string(local + Addr.name)
        local_player.health = proc.read_int(local + Addr.health)
        local_player.pos_x = proc.read_float(local + Addr.pos)
        local_player.pos_y = proc.read_float(local + Addr.pos + 4)
        local_player.pos_z = proc.read_float(local + Addr.pos + 8)
    t_end = time()
    print(f"[R] pyMem (Local: {vars(local_player)}): Memory: {t_end - t_start} sec")
    for _ in range(n):
        proc.write_int(local + Addr.health, local_player.health + 1)
        proc.write_float(local + Addr.pos, local_player.pos_x)
        proc.write_float(local + Addr.pos + 4, local_player.pos_y)
        proc.write_float(local + Addr.pos + 8, local_player.pos_z)
    t_end2 = time()
    print(f"[W] pyMem {t_end2 - t_end} sec")
    proc.close_process()


def measure_ctypes_mem(n):
    local_player = LocalPlayer()
    proc = memory.Memory("ac_client.exe")
    base = proc.base
    local = proc.read(base + Addr.local_player, c_int())
    t_start = time()
    for _ in range(n):
        local_player.name = proc.read_string(local + Addr.name)
        local_player.health = proc.read(local + Addr.health, c_int())
        local_player.pos_x = proc.read(local + Addr.pos, c_float())
        local_player.pos_y = proc.read(local + Addr.pos + 4, c_float())
        local_player.pos_z = proc.read(local + Addr.pos + 8, c_float())
    t_end = time()
    print(f"[R] cTypes Mem (Local: {vars(local_player)}): Memory: {t_end - t_start} sec")
    for _ in range(n):
        proc.write(local + Addr.health, c_int(local_player.health + 1))
        proc.write(local + Addr.pos, c_float(local_player.pos_x))
        proc.write(local + Addr.pos + 4, c_float(local_player.pos_y))
        proc.write(local + Addr.pos + 8 , c_float(local_player.pos_z))
    t_end2 = time()
    print(f"[W] cTypes Mem {t_end2 - t_end} sec")
    proc.close()


def measure_ctypes_mem_struct(n):
    local_player = LocalPlayer()
    local_player_struct = LocalStruct()
    proc = memory.Memory("ac_client.exe")
    base = proc.base
    local = proc.read(base + Addr.local_player, c_int())
    t_start = time()
    for _ in range(n):
        local_player_struct = proc.read(local, LocalStruct(), False)
    local_player.name = local_player_struct.name.decode()
    local_player.health = local_player_struct.health
    local_player.pos_x = local_player_struct.pos_x
    local_player.pos_y = local_player_struct.pos_y
    local_player.pos_z = local_player_struct.pos_z
    t_end = time()
    print(f"[R] cTypes Mem Struct (Local: {vars(local_player)}): Memory: {t_end - t_start} sec")
    local_player_struct.health = c_int(255)
    for _ in range(n):
        proc.write(local, local_player_struct)
    t_end2 = time()
    print(f"[W] cTypes Mem Struct {t_end2 - t_end} sec")
    proc.close()


if __name__ == "__main__":
    its = 100000
    measure_pymem(its)
    measure_ctypes_mem(its)
    measure_ctypes_mem_struct(its)