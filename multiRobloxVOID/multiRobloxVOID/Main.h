#pragma once
#pragma once
#ifndef __MAIN_H__
#define __MAIN_H__

/*
https://www.unknowncheats.me/forum/general-programming-and-reversing/202534-mutexkiller.html
	Please note, that most of the structures here don't have a documentation in the APIs.
*/
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tlhelp32.h>
#include <tchar.h>

template<typename T>
constexpr auto NT_SUCCESS(T x) { return ((x) >= 0); }
constexpr auto STATUS_INFO_LENGTH_MISMATCH = 0xc0000004;

constexpr auto SystemHandleInformation = 16;
constexpr auto ObjectBasicInformation = 0;
constexpr auto ObjectNameInformation = 1;
constexpr auto ObjectTypeInformation = 2;

/*
	Call NtQuerySystemInformation with SystemHandleInformation. This will give you a list of handles opened by every single process.
	Here is the definition:
*/
typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);

/*
	After you have the list of handles, you will probably want to get the types and names of the handles.
	There is no way to do this without duplicating the handle into your own process, so we can do that using DuplicateHandle / NtDuplicateObject.
	Here is the definition:
*/
typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);

/*
	To get the names of other objects, you must duplicate the handle and use NtQueryObject with ObjectNameInformation, to get the name of the object.
	You will get a UNICODE_STRING back. IMPORTANT: NtQueryObject may hang on file handles pointing to named pipes.
	To fix this, do not query any file handles opened with an access (GrantedAccess) of 0x0012019f.
	This problem only appears for ObjectNameInformation, not ObjectTypeInformation.
*/
typedef NTSTATUS(NTAPI* _NtQueryObject)(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

/* The following structure is actually called SYSTEM_HANDLE_TABLE_ENTRY_INFO, but SYSTEM_HANDLE is shorter. */
typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

/* Needed for ObjectTypeInformation */
typedef enum _POOL_TYPE
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, * PPOOL_TYPE;

/*
	Call NtQueryObject with ObjectTypeInformation. You will get this structure back:
*/
typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

#endif