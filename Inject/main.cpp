#include "Inject.h"
#include <iostream>
#include <tchar.h>

#pragma warning(disable:4703) //Uninitialize variable

int _tmain(int argc, TCHAR* argv)
{
	if (EnableDebugPrivilege(_T("SeDebugPrivilege"), TRUE) == FALSE)
	{
		return 0;
	}

	DWORD ProcessIdentify = 0;
	_tprintf(_T("Input ProcessIdentify:\r\n"));
	_tscanf_s(_T("%d"), &ProcessIdentify, sizeof(DWORD));

#ifdef _WIN64
	LPCTSTR DllFullPath = _T("Reflective_dll.dll");
#else
	LPCTSTR DllFullPath = _T("Reflective_dll.dll");
#endif
	HANDLE ThreadHandle;
	HANDLE ProcessHandle;
	DWORD FileDataLength;
	LPVOID FileData;
	HANDLE FileHandle = CreateFile(DllFullPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (FileHandle == INVALID_HANDLE_VALUE)
	{
		_tprintf(_T("CreateFile() Error\r\n"));
		goto Exit;
	}

	FileDataLength = GetFileSize(FileHandle, NULL);
	if (FileDataLength == INVALID_FILE_SIZE || FileDataLength == 0)
	{
		_tprintf(_T("GetFileSize() Error\r\n"));
		goto Exit;
	}

	FileData = HeapAlloc(GetProcessHeap(), 0, FileDataLength);
	if (!FileData)
	{
		_tprintf(_T("HeapAlloc() Error\r\n"));
		goto Exit;
	}
	DWORD NumberOfBytesRead;
	if (ReadFile(FileHandle, FileData, FileDataLength, &NumberOfBytesRead, NULL) == FALSE)
	{
		_tprintf(_T("ReadFile() Error\r\n"));
		goto Exit;
	}

	ProcessHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, ProcessIdentify);
	if (!ProcessHandle)
	{
		_tprintf(_T("OpenProcess() Error\r\n"));
		goto Exit;
	}

	ThreadHandle = LoadRemoteLibrary(ProcessHandle, FileData, FileDataLength, NULL, MY_FUNCTION_HASH, (LPVOID)_T("911"), (_tcslen(_T("911")) + 1) * sizeof(TCHAR));
	if (!ThreadHandle)
	{
		_tprintf(_T("LoadRemoteLibrary() Error\r\n"));
		goto Exit;
	}

	WaitForSingleObject(ThreadHandle, INFINITE);
	DWORD ExitCode;
	if (!GetExitCodeThread(ThreadHandle, &ExitCode))
	{
		_tprintf(_T("Input AnyKey To Exit\r\n"));
	}
	_gettchar();
Exit:
	{
		if (FileData)
		{
			HeapFree(GetProcessHeap(), 0, FileData);
		}
		if (FileHandle != NULL)
		{
			CloseHandle(FileHandle);
			FileHandle = NULL;
		}
		if (ProcessHandle)
		{
			CloseHandle(ProcessHandle);
			ProcessHandle = NULL;
		}
		return 0;
	}
}