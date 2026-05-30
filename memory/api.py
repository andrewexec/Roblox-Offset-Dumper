import re
import platform
import ctypes

system = platform.system()

if system == "Windows":
    import win32job
    windll = ctypes.windll
    kernel32 = windll.kernel32
    ntdll = windll.ntdll

    ALLOWED_PROTECTIONS = [
        0x02,  # PAGE_READONLY
        0x04,  # PAGE_READWRITE
        0x20,  # PAGE_EXECUTE_READONLY
        0x40,  # PAGE_EXECUTE_READWRITE
    ]

    PROTECTIONS = {
        "READ_ONLY": 0x02,
        "READ_WRITE": 0x04,
        "EXEC_READ_ONLY": 0x20,
        "EXEC_READ_WRITE": 0x40,
    }

    JobObjectFreezeInformation = 18

    class MEMORY_BASIC_INFORMATION32(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_ulong),
            ("AllocationBase", ctypes.c_ulong),
            ("AllocationProtect", ctypes.c_ulong),
            ("RegionSize", ctypes.c_ulong),
            ("State", ctypes.c_ulong),
            ("Protect", ctypes.c_ulong),
            ("Type", ctypes.c_ulong),
        ]

    class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_ulonglong),
            ("AllocationBase", ctypes.c_ulonglong),
            ("AllocationProtect", ctypes.c_ulong),
            ("RegionSize", ctypes.c_ulonglong),
            ("State", ctypes.c_ulong),
            ("Protect", ctypes.c_ulong),
            ("Type", ctypes.c_ulong),
        ]

    ptr_size = ctypes.sizeof(ctypes.c_void_p)
    if ptr_size == 8:
        MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION64
    else:
        MEMORY_BASIC_INFORMATION = MEMORY_BASIC_INFORMATION32

    kernel32.VirtualQueryEx.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION),
        ctypes.c_ulong,
    ]
    kernel32.VirtualQueryEx.restype = ctypes.c_ulong
    kernel32.VirtualAllocEx.restype = ctypes.c_void_p

elif system == "Darwin":
    import ctypes.util
    import os
    import signal

    libc_path = ctypes.util.find_library("c") or "/usr/lib/libc.dylib"
    libc = ctypes.CDLL(libc_path, use_errno=True)

    mach_task_self = libc.mach_task_self
    mach_task_self.restype = ctypes.c_uint

    task_for_pid = libc.task_for_pid
    task_for_pid.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.POINTER(ctypes.c_uint)]
    task_for_pid.restype = ctypes.c_int

    mach_vm_read_overwrite = libc.mach_vm_read_overwrite
    mach_vm_read_overwrite.argtypes = [
        ctypes.c_uint,
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.POINTER(ctypes.c_uint64),
    ]
    mach_vm_read_overwrite.restype = ctypes.c_int

    mach_vm_write = libc.mach_vm_write
    mach_vm_write.argtypes = [
        ctypes.c_uint,
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_uint32,
    ]
    mach_vm_write.restype = ctypes.c_int

    mach_vm_protect = libc.mach_vm_protect
    mach_vm_protect.argtypes = [
        ctypes.c_uint,
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_int,
        ctypes.c_int,
    ]
    mach_vm_protect.restype = ctypes.c_int

else:
    raise NotImplementedError("Only Windows and macOS are supported")


class Memopy:
    ctypes = ctypes
    process_handle = -1

    def __init__(self, process: int):
        self.pid = process
        self.task = None

        if system == "Windows":
            self.process_handle = kernel32.OpenProcess(0x1F0FFF, False, process)
            self.hJob = kernel32.CreateJobObjectA(None, None)
            print("[+] Freeze Job Created")
        elif system == "Darwin":
            self.process_handle = 0
            self.task = ctypes.c_uint(0)

    def update_pid(self, pid: int):
        self.pid = pid
        if system == "Windows":
            self.process_handle = kernel32.OpenProcess(0x1F0FFF, False, pid)
        else:
            task = ctypes.c_uint(0)
            result = task_for_pid(mach_task_self(), pid, ctypes.byref(task))
            if result != 0:
                self.process_handle = 0
                self.task = ctypes.c_uint(0)
            else:
                self.process_handle = pid
                self.task = task

    def suspend(self):
        if system == "Windows":
            job_info = JOBOBJECT_FREEZE_INFORMATION()
            job_info.Flags = 1
            job_info.Freeze = True
            kernel32.SetInformationJobObject(self.hJob, JobObjectFreezeInformation, ctypes.byref(job_info), ctypes.sizeof(job_info))
            kernel32.AssignProcessToJobObject(self.hJob, self.process_handle)
        else:
            try:
                os.kill(self.pid, signal.SIGSTOP)
            except Exception:
                pass

    def resume(self):
        if system == "Windows":
            job_info = JOBOBJECT_FREEZE_INFORMATION()
            job_info.Flags = 1
            job_info.Freeze = False
            ctypes.windll.kernel32.SetInformationJobObject(self.hJob, JobObjectFreezeInformation, ctypes.byref(job_info), ctypes.sizeof(job_info))
            kernel32.AssignProcessToJobObject(self.hJob, self.process_handle)
        else:
            try:
                os.kill(self.pid, signal.SIGCONT)
            except Exception:
                pass

    def cleanup(self):
        if system == "Windows":
            kernel32.CloseHandle(self.hJob)
            kernel32.CloseHandle(self.process_handle)

    def virtual_query(self, address: int):
        if system == "Windows":
            memory_basic_info = MEMORY_BASIC_INFORMATION()
            kernel32.VirtualQueryEx(
                self.process_handle,
                ctypes.c_void_p(address),
                ctypes.byref(memory_basic_info),
                ctypes.sizeof(memory_basic_info),
            )
            return memory_basic_info
        raise NotImplementedError("virtual_query is not supported on macOS")

    def pattern_scan(self, pattern: bytes, single=True):
        if system == "Windows":
            region = 0
            found = [] if not single else None
            while region < 0x7FFFFFFF0000:
                mbi = self.virtual_query(region)
                if mbi.State != 0x1000 or mbi.Protect not in ALLOWED_PROTECTIONS:
                    region += mbi.RegionSize
                    continue

                current_bytes = self.read_bytes(region, mbi.RegionSize)
                if single:
                    match = re.search(pattern, current_bytes, re.DOTALL)
                    if match:
                        found = region + match.span()[0]
                        break
                else:
                    for match in re.finditer(pattern, current_bytes, re.DOTALL):
                        found_address = region + match.span()[0]
                        found.append(found_address)

                region += mbi.RegionSize
            return found

        raise NotImplementedError("pattern_scan is not supported on macOS")

    def virtual_protect(self, address: int, size: int, protect_val: int):
        if system == "Windows":
            old_prot_val = ctypes.c_ulong()
            kernel32.VirtualProtectEx(
                self.process_handle,
                ctypes.c_void_p(address),
                size,
                ctypes.c_ulong(protect_val),
                ctypes.byref(old_prot_val),
            )
            return old_prot_val.value
        return 0

    def unlock_memory(self, address: int, size: int):
        if system == "Windows":
            return ntdll.NtUnlockVirtualMemory(
                self.process_handle,
                ctypes.c_void_p(address),
                size,
                0x01,
            )
        return 0

    def allocate_memory(self, size: int, address: int = None) -> int:
        if system == "Windows":
            return kernel32.VirtualAllocEx(
                self.process_handle,
                (ctypes.c_void_p(address) if address else None),
                size,
                0x1000 | 0x2000,
                PROTECTIONS["READ_WRITE"],
            )
        raise NotImplementedError("allocate_memory is not supported on macOS")

    def free_memory(self, address: int, size: int):
        if system == "Windows":
            return kernel32.VirtualFreeEx(
                self.process_handle,
                ctypes.c_void_p(address),
                size,
                0x4000,
            )
        raise NotImplementedError("free_memory is not supported on macOS")

    def read_memory(self, buffer, address: int):
        size = ctypes.sizeof(buffer)
        if system == "Windows":
            kernel32.ReadProcessMemory(
                self.process_handle,
                ctypes.c_void_p(address),
                ctypes.byref(buffer),
                size,
                None,
            )
            self.unlock_memory(address, size)
            return

        out_size = ctypes.c_uint64(0)
        read_address = ctypes.c_uint64(ctypes.addressof(buffer))
        result = mach_vm_read_overwrite(
            self.task.value,
            ctypes.c_uint64(address),
            ctypes.c_uint64(size),
            read_address,
            ctypes.byref(out_size),
        )
        if result != 0:
            raise OSError(f"mach_vm_read_overwrite failed: {result}")

    def write_memory(self, buffer, address: int) -> None:
        size = ctypes.sizeof(buffer)
        if system == "Windows":
            old_prot = self.virtual_protect(address, size, PROTECTIONS["READ_WRITE"])
            kernel32.WriteProcessMemory(
                self.process_handle,
                ctypes.c_void_p(address),
                ctypes.pointer(buffer),
                size,
                None,
            )
            self.virtual_protect(address, size, old_prot)
            return

        source_address = ctypes.c_uint64(ctypes.addressof(buffer))
        result = mach_vm_write(self.task.value, ctypes.c_uint64(address), source_address, ctypes.c_uint32(size))
        if result != 0:
            raise OSError(f"mach_vm_write failed: {result}")

    def read_byte(self, address: int) -> bytes:
        buffer = ctypes.c_char()
        self.read_memory(buffer, address)
        return buffer.value[0:1]

    def read_bytes(self, address: int, length=4096) -> bytes:
        if system == "Windows":
            buffer = (length * ctypes.c_char)()
            self.read_memory(buffer, address)
            return buffer.raw

        buffer = ctypes.create_string_buffer(length)
        out_size = ctypes.c_uint64(0)
        result = mach_vm_read_overwrite(
            self.task.value,
            ctypes.c_uint64(address),
            ctypes.c_uint64(length),
            ctypes.c_uint64(ctypes.addressof(buffer)),
            ctypes.byref(out_size),
        )
        if result != 0:
            raise OSError(f"mach_vm_read_overwrite failed: {result}")
        return buffer.raw[: out_size.value]

    def read_string(self, address: int, length=100) -> str:
        return self.read_bytes(address, length).split(b"\x00")[0].decode(errors="ignore")

    def read_double(self, address: int) -> float:
        buffer = ctypes.c_double()
        self.read_memory(buffer, address)
        return buffer.value

    def read_float(self, address: int) -> float:
        buffer = ctypes.c_float()
        self.read_memory(buffer, address)
        return buffer.value

    def read_long(self, address: int) -> int:
        buffer = ctypes.c_long()
        self.read_memory(buffer, address)
        return buffer.value

    def read_longlong(self, address: int) -> int:
        buffer = ctypes.c_longlong()
        self.read_memory(buffer, address)
        return buffer.value

    def write_byte(self, address: int, value):
        buffer = ctypes.c_char(value)
        self.write_memory(buffer, address)

    def write_bytes(self, address: int, value: bytes):
        buffer = (len(value) * ctypes.c_char)(*value)
        self.write_memory(buffer, address)

    def write_string(self, address: int, value: str):
        new_string = value.encode(errors="ignore") + b"\x00"
        self.write_bytes(address, new_string)

    def write_double(self, address: int, value: float):
        buffer = ctypes.c_double(value)
        self.write_memory(buffer, address)

    def write_float(self, address: int, value: float):
        buffer = ctypes.c_float(value)
        self.write_memory(buffer, address)

    def write_long(self, address: int, value: int):
        buffer = ctypes.c_long(value)
        self.write_memory(buffer, address)

    def write_longlong(self, address: int, value: int):
        buffer = ctypes.c_longlong(value)
        self.write_memory(buffer, address)
