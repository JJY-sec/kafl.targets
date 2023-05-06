/*

Copyright (C) 2017 Robert Gawlik

This file is part of kAFL Fuzzer (kAFL).

QEMU-PT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

QEMU-PT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include "../../../nyx_api.h"
#include <psapi.h>
#include <virtdisk.h>
#include <sddl.h>


#define ARRAY_SIZE 1024

#define INFO_SIZE                       (128 << 10)				/* 128KB info string */

#define PAYLOAD_MAX_SIZE (128*1024)

#define IOCTL_KAFL_INPUT    (ULONG) CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
typedef enum _ATTACH_VIRTUAL_DISK_VERSION {
  ATTACH_VIRTUAL_DISK_VERSION_UNSPECIFIED = 0,
  ATTACH_VIRTUAL_DISK_VERSION_1 = 1,
  ATTACH_VIRTUAL_DISK_VERSION_2
} ATTACH_VIRTUAL_DISK_VERSION;
typedef enum _VIRTUAL_DISK_ACCESS_MASK {
  VIRTUAL_DISK_ACCESS_NONE = 0x00000000,
  VIRTUAL_DISK_ACCESS_ATTACH_RO = 0x00010000,
  VIRTUAL_DISK_ACCESS_ATTACH_RW = 0x00020000,
  VIRTUAL_DISK_ACCESS_DETACH = 0x00040000,
  VIRTUAL_DISK_ACCESS_GET_INFO = 0x00080000,
  VIRTUAL_DISK_ACCESS_CREATE = 0x00100000,
  VIRTUAL_DISK_ACCESS_METAOPS = 0x00200000,
  VIRTUAL_DISK_ACCESS_READ = 0x000d0000,
  VIRTUAL_DISK_ACCESS_ALL = 0x003f0000,
  VIRTUAL_DISK_ACCESS_WRITABLE = 0x00320000
} VIRTUAL_DISK_ACCESS_MASK;
typedef enum _OPEN_VIRTUAL_DISK_VERSION {
  OPEN_VIRTUAL_DISK_VERSION_UNSPECIFIED = 0,
  OPEN_VIRTUAL_DISK_VERSION_1 = 1,
  OPEN_VIRTUAL_DISK_VERSION_2 = 2,
  OPEN_VIRTUAL_DISK_VERSION_3 = 3
} OPEN_VIRTUAL_DISK_VERSION;
typedef enum _ATTACH_VIRTUAL_DISK_FLAG {
  ATTACH_VIRTUAL_DISK_FLAG_NONE = 0x00000000,
  ATTACH_VIRTUAL_DISK_FLAG_READ_ONLY = 0x00000001,
  ATTACH_VIRTUAL_DISK_FLAG_NO_DRIVE_LETTER = 0x00000002,
  ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME = 0x00000004,
  ATTACH_VIRTUAL_DISK_FLAG_NO_LOCAL_HOST = 0x00000008,
  ATTACH_VIRTUAL_DISK_FLAG_NO_SECURITY_DESCRIPTOR = 0x00000010,
  ATTACH_VIRTUAL_DISK_FLAG_BYPASS_DEFAULT_ENCRYPTION_POLICY = 0x00000020,
  ATTACH_VIRTUAL_DISK_FLAG_NON_PNP,
  ATTACH_VIRTUAL_DISK_FLAG_RESTRICTED_RANGE,
  ATTACH_VIRTUAL_DISK_FLAG_SINGLE_PARTITION,
  ATTACH_VIRTUAL_DISK_FLAG_REGISTER_VOLUME
} ATTACH_VIRTUAL_DISK_FLAG;

typedef enum _OPEN_VIRTUAL_DISK_FLAG {
  OPEN_VIRTUAL_DISK_FLAG_NONE = 0x00000000,
  OPEN_VIRTUAL_DISK_FLAG_NO_PARENTS = 0x00000001,
  OPEN_VIRTUAL_DISK_FLAG_BLANK_FILE = 0x00000002,
  OPEN_VIRTUAL_DISK_FLAG_BOOT_DRIVE = 0x00000004,
  OPEN_VIRTUAL_DISK_FLAG_CACHED_IO = 0x00000008,
  OPEN_VIRTUAL_DISK_FLAG_CUSTOM_DIFF_CHAIN = 0x00000010,
  OPEN_VIRTUAL_DISK_FLAG_PARENT_CACHED_IO = 0x00000020,
  OPEN_VIRTUAL_DISK_FLAG_VHDSET_FILE_ONLY = 0x00000040,
  OPEN_VIRTUAL_DISK_FLAG_IGNORE_RELATIVE_PARENT_LOCATOR = 0x00000080,
  OPEN_VIRTUAL_DISK_FLAG_NO_WRITE_HARDENING = 0x00000100,
  OPEN_VIRTUAL_DISK_FLAG_SUPPORT_COMPRESSED_VOLUMES,
  OPEN_VIRTUAL_DISK_FLAG_SUPPORT_SPARSE_FILES_ANY_FS,
  OPEN_VIRTUAL_DISK_FLAG_SUPPORT_ENCRYPTED_FILES
} OPEN_VIRTUAL_DISK_FLAG;

#define VIRTUAL_STORAGE_TYPE_DEVICE_UNKNOWN 0
#define VIRTUAL_STORAGE_TYPE_DEVICE_ISO 1
#define VIRTUAL_STORAGE_TYPE_DEVICE_VHD 2
#define VIRTUAL_STORAGE_TYPE_DEVICE_VHDX 3

GUID VIRTUAL_STORAGE_TYPE_VENDOR_UNKNOWN = {0x00000000, 0x0000, 0x0000, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

#define SDDL_REVISION_1 1


typedef struct _VIRTUAL_STORAGE_TYPE {
  ULONG DeviceId;
  GUID  VendorId;
} VIRTUAL_STORAGE_TYPE, *PVIRTUAL_STORAGE_TYPE;


typedef struct _OPEN_VIRTUAL_DISK_PARAMETERS {
  OPEN_VIRTUAL_DISK_VERSION Version;
  union {
    struct {
      ULONG RWDepth;
    } Version1;
    struct {
      BOOL GetInfoOnly;
      BOOL ReadOnly;
      GUID ResiliencyGuid;
    } Version2;
  };
} OPEN_VIRTUAL_DISK_PARAMETERS, *POPEN_VIRTUAL_DISK_PARAMETERS;
typedef struct _ATTACH_VIRTUAL_DISK_PARAMETERS {
  ATTACH_VIRTUAL_DISK_VERSION Version;
  union {
    struct {
      ULONG Reserved;
    } Version1;
    struct {
      ULONGLONG RestrictedOffset;
      ULONGLONG RestrictedLength;
    } Version2;
  };
} ATTACH_VIRTUAL_DISK_PARAMETERS, *PATTACH_VIRTUAL_DISK_PARAMETERS;


PCSTR ntoskrnl = "C:\\Windows\\System32\\ntoskrnl.exe";
PCSTR kernel_func1 = "KeBugCheck";
PCSTR kernel_func2 = "KeBugCheckEx";
void * IP0_START = NULL;
void * IP0_END = NULL;
FARPROC KernGetProcAddress(HMODULE kern_base, LPCSTR function){
    // error checking? bah...
    HMODULE kernel_base_in_user_mode = LoadLibraryA(ntoskrnl);
    return (FARPROC)((PUCHAR)GetProcAddress(kernel_base_in_user_mode, function) - (PUCHAR)kernel_base_in_user_mode + (PUCHAR)kern_base);
}   


UINT64 resolve_KeBugCheck(PCSTR kfunc){
    LPVOID drivers[ARRAY_SIZE];
    DWORD cbNeeded;
    FARPROC KeBugCheck = NULL;
    int cDrivers, i;

    if( EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)){ 
        TCHAR szDriver[ARRAY_SIZE];
        cDrivers = cbNeeded / sizeof(drivers[0]);
        for (i=0; i < cDrivers; i++){
            if(GetDeviceDriverFileName(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0]))){
            // assuming ntoskrnl.exe is first entry seems save (FIXME)
                if (i == 0){
                    KeBugCheck = KernGetProcAddress((HMODULE)drivers[i], kfunc);
                    if (!KeBugCheck){
                        printf("[-] w00t?");
                        ExitProcess(0);
                    }
                    break;
                }
            }
        }
    }
    else{
        printf("[-] EnumDeviceDrivers failed; array size needed is %d\n", (UINT32)(cbNeeded / sizeof(LPVOID)));
        ExitProcess(0);
    }

    return  (UINT64) KeBugCheck;
}


void init_agent_handshake() {

    hprintf("Initiate fuzzer handshake...\n");

    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

    // Submit our CR3
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

    // Tell KAFL we're running in 64bit mode
	kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);

    /* Request information on available (host) capabilites (not optional) */
	volatile host_config_t host_config;
	kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);
	if (host_config.host_magic != NYX_HOST_MAGIC ||
	    host_config.host_version != NYX_HOST_VERSION) {
		hprintf("host_config magic/version mismatch!\n");
		habort("GET_HOST_CONFIG magic/version mismatch!\n");
	}
	hprintf("\thost_config.bitmap_size: 0x%lx\n", host_config.bitmap_size);
	hprintf("\thost_config.ijon_bitmap_size: 0x%lx\n", host_config.ijon_bitmap_size);
	hprintf("\thost_config.payload_buffer_size: 0x%lx\n", host_config.payload_buffer_size);

    /* reserved guest memory must be at least as large as host SHM view */
	if (PAYLOAD_MAX_SIZE < host_config.payload_buffer_size) {
		habort("Insufficient guest payload buffer!\n");
	}

    /* submit agent configuration */
	volatile agent_config_t agent_config = {0};
	agent_config.agent_magic = NYX_AGENT_MAGIC;
	agent_config.agent_version = NYX_AGENT_VERSION;

	agent_config.agent_tracing = 0; // trace by host!
	agent_config.agent_ijon_tracing = 0; // no IJON
	agent_config.agent_non_reload_mode = 1; // allow persistent
	agent_config.coverage_bitmap_size = host_config.bitmap_size;

	kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);

}


typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;
 
typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

char * saved=NULL;
void set_ip_range() {
    char* info_buffer = (char*)VirtualAlloc(0, INFO_SIZE, MEM_COMMIT, PAGE_READWRITE);
    memset(info_buffer, 0xff, INFO_SIZE);
    memset(info_buffer, 0x00, INFO_SIZE);
    int pos = 0;

   LPVOID drivers[ARRAY_SIZE];
   DWORD cbNeeded;
   int cDrivers, i;
   NTSTATUS status;

   if( EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
   { 
        TCHAR szDriver[ARRAY_SIZE];

        cDrivers = cbNeeded / sizeof(drivers[0]);
        PRTL_PROCESS_MODULES ModuleInfo;
 
        ModuleInfo=(PRTL_PROCESS_MODULES)VirtualAlloc(NULL,1024*1024,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
     
        if(!ModuleInfo){
            hprintf("VirtualAlloc fail\n");
            goto fail;
        }
     
        if(!NT_SUCCESS(status=NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11,ModuleInfo,1024*1024,NULL))){
            hprintf("NtQuerySystemInformation fail\n");
            VirtualFree(ModuleInfo,0,MEM_RELEASE);
            goto fail;
        }

        pos += sprintf(info_buffer + pos, "kAFL Windows x86-64 Kernel Addresses (%d Drivers)\n\n", cDrivers);
        //_tprintf(TEXT("kAFL Windows x86-64 Kernel Addresses (%d Drivers)\n\n"), cDrivers);      
        pos += sprintf(info_buffer + pos, "START-ADDRESS\t\tEND-ADDRESS\t\tDRIVER\n");
        //_tprintf(TEXT("START-ADDRESS\t\tEND-ADDRESS\t\tDRIVER\n"));      
        for (i=0; i < cDrivers; i++ ){
            pos += sprintf(info_buffer + pos, "0x%p\t0x%p\t%s\n", drivers[i], ((UINT64)drivers[i]) + ModuleInfo->Modules[i].ImageSize, ModuleInfo->Modules[i].FullPathName+ModuleInfo->Modules[i].OffsetToFileName);
            saved = strdup(ModuleInfo->Modules[i].FullPathName);
            //TARGET ADDRESS
            hprintf("look driver %s\n",ModuleInfo->Modules[i].FullPathName);
            if(strstr(ModuleInfo->Modules[i].FullPathName,"Ntfs.sys") > 0 ) {
                uint64_t buffer[3];
                buffer[0] = drivers[i];
                buffer[1] = drivers[i] + ModuleInfo->Modules[i].ImageSize;
                buffer[2] = 0;
                IP0_START = drivers[i];
                IP0_END = drivers[i]+ ModuleInfo->Modules[i].ImageSize;
                kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (UINT64)buffer);
                return;
            }
            //_tprintf(TEXT("0x%p\t0x%p\t%s\n"), drivers[i], drivers[i]+ModuleInfo->Modules[i].ImageSize, ModuleInfo->Modules[i].FullPathName+ModuleInfo->Modules[i].OffsetToFileName);
        }
   }
   else {
        goto fail;
   }
   fail:
        habort("FAIL! NO MATCH!\n");
        exit(1);
}

void init_panic_handlers() {
    UINT64 panic_kebugcheck = 0x0;
    UINT64 panic_kebugcheck2 = 0x0;
    panic_kebugcheck = resolve_KeBugCheck(kernel_func1);
    panic_kebugcheck2 = resolve_KeBugCheck(kernel_func2);
    hprintf("Submitting bug check handlers\n");
    /* submit panic address */
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, panic_kebugcheck);
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, panic_kebugcheck2);
}
int mount_fs(){
    /*
        https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Hyper-V/Storage/cpp/AttachVirtualDisk.cpp
    */
    OPEN_VIRTUAL_DISK_PARAMETERS openParameters;
    VIRTUAL_DISK_ACCESS_MASK accessMask;
    ATTACH_VIRTUAL_DISK_PARAMETERS attachParameters;
    PSECURITY_DESCRIPTOR sd;
    VIRTUAL_STORAGE_TYPE storageType;
    LPCTSTR extension;
    HANDLE vhdHandle;
    ATTACH_VIRTUAL_DISK_FLAG attachFlags;
    DWORD opStatus;
    vhdHandle = INVALID_HANDLE_VALUE;
    sd = NULL;


    storageType.DeviceId = VIRTUAL_STORAGE_TYPE_DEVICE_UNKNOWN;
    storageType.VendorId = VIRTUAL_STORAGE_TYPE_VENDOR_UNKNOWN;
    
    LPCWSTR VirtualDiskPath = L"C:\\Temp\\input.vhd";
    
    accessMask = VIRTUAL_DISK_ACCESS_READ;
    
    memset(&openParameters, 0, sizeof(openParameters));
    openParameters.Version = OPEN_VIRTUAL_DISK_VERSION_2;
    openParameters.Version2.GetInfoOnly = FALSE;


    OpenVirtualDisk(
            &storageType,
            VirtualDiskPath,
            accessMask,
            OPEN_VIRTUAL_DISK_FLAG_NONE , //TODO
            &openParameters,
            &vhdHandle
        );
    
    if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
            L"O:BAG:BAD:(A;;GA;;;WD)",
            SDDL_REVISION_1,
            &sd,
            NULL))
    {
        return;
    }
    
    memset(&attachParameters, 0, sizeof(attachParameters));
    attachParameters.Version = ATTACH_VIRTUAL_DISK_VERSION_1;
    attachFlags = ATTACH_VIRTUAL_DISK_FLAG_PERMANENT_LIFETIME;
    
    opStatus = AttachVirtualDisk(
        vhdHandle,
        sd,
        attachFlags,
        0,
        &attachParameters,
        NULL);
    
}

int main(int argc, char** argv)
{
    Sleep(30*1000);
    kAFL_payload* payload_buffer = (kAFL_payload*)VirtualAlloc(0, PAYLOAD_MAX_SIZE, MEM_COMMIT, PAGE_READWRITE);
    //LPVOID payload_buffer = (LPVOID)VirtualAlloc(0, PAYLOAD_SIZE, MEM_COMMIT, PAGE_READWRITE);
    memset(payload_buffer, 0x0, PAYLOAD_MAX_SIZE);

    /* open vulnerable driver */
    HANDLE kafl_vuln_handle = NULL;
    BOOL status = -1;
    init_agent_handshake();

    init_panic_handlers();

    /* this hypercall submits the current CR3 value */ 
    hprintf("submit cr3\n");
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);
    /* submit the guest virtual address of the payload buffer */
    hprintf("get_payload\n");
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINT64)payload_buffer);

    // Submit PT ranges
    hprintf("set_ip_range\n");
    set_ip_range();
    hprintf("snapshot here\n");
    // Snapshot here
    kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
    printf("requesd new payload\n");
    /* request new payload (*blocking*) */
    hprintf("%s\nSTART = %p\nEND = %p\n",saved,IP0_START,IP0_END);
    hprintf("fuzz start\n");
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0); 
    
    const wchar_t* filePath = L"C:\\Temp\\input.vhd";
    DWORD bytesWritten = 0;

    HANDLE fileHandle = CreateFile(
        filePath,
        GENERIC_WRITE,
        0,
        NULL,
        CREATE_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (!WriteFile(fileHandle,payload_buffer->data ,payload_buffer->size, &bytesWritten, NULL)) {
        CloseHandle(fileHandle);
        return 1;
    }
    CloseHandle(fileHandle);
    mount_fs();
    /* inform fuzzer about finished fuzzing iteration */
    // Will reset back to start of snapshot here
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    return 0;
}

