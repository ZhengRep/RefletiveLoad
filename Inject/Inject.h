#pragma once
#include <windows.h>

#pragma warning(disable:4996) //GetVersionEx is discard

#define MY_FUNCTION_HASH		0x6654bba6 // hash of "MyFunction"
enum 
{
	UNKNOWN,
	X86,
	X64
};

#define DEREFERENCE   (Value)		*(UINT_PTR *)(Value)
#define DEREFERENCE_64(Value)		*(DWORD64 *)(Value)
#define DEREFERENCE_32(Value)		*(DWORD *)(Value)
#define DEREFERENCE_16(Value)		*(WORD *)(Value)
#define DEREFERENCE_8 (Value)		*(BYTE *)(Value)

typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS)		(HANDLE, PBOOL);
typedef BOOL(WINAPI* LPFN_FUNCTIONX64)			(DWORD ParameterData);
typedef DWORD(WINAPI* LPFN_EXECUTEX64)			(LPFN_FUNCTIONX64 FunctionX64, DWORD ParameterData);

typedef struct _WOW64CONTEXT
{
	union
	{
		HANDLE ProcessHandle;
		BYTE   Padding[8];
	}u1;
	union
	{
		LPVOID ThreadProcedure;
		BYTE   Padding[8];
	}u2;
	union
	{
		LPVOID ParameterData;
		BYTE   Padding[8];
	}u3;
	union
	{
		HANDLE ThreadHandle;
		BYTE   Padding[8];
	}u4;
} WOW64CONTEXT, * LPWOW64CONTEXT;

HANDLE WINAPI LoadRemoteLibrary(
	HANDLE ProcessHandle,
	LPVOID FileData,   //Dll文件数据
	DWORD  FileDataLength,
	LPVOID ParameterData,
	DWORD  FunctionHash,
	LPVOID UserData,
	DWORD  UserDataLength
);
DWORD CreateBootstrap(
	LPBYTE BootstrapData,
	DWORD BootstrapDataLength,
	DWORD TargetArchitecture,
	ULONG_PTR ParameterData,
	ULONG_PTR BufferData,
	DWORD FunctionHashValue,
	ULONG_PTR UserData,
	DWORD UserDataLength,
	ULONG_PTR ReflectiveLoader
);
BOOL EnableDebugPrivilege(IN const TCHAR* PriviledgeName, BOOL IsEnable);
DWORD GetReflectiveLoaderRaw(VOID* VirtualAddress);
DWORD RvaToRaw(DWORD Rva, UINT_PTR ImageBase);
BOOL Wow64CreateRemoteThread(HANDLE ProcessHandle, LPVOID ThreadProcedure, LPVOID ParameterData, HANDLE* ThreadHandle);