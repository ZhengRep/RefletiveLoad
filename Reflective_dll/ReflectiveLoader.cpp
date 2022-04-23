#include "pch.h"
#include "ReflectiveLoader.h"

__declspec(dllexport)
VOID WINAPI ReflectiveLoader(LPVOID ParameterData, ULONG_PTR BufferData, DWORD FunctionHashValue, LPVOID UserData, DWORD UserDataLength)
{
	REFLECTIVELOADER::LPFN_LOADLIBRARYA   LoadLibraryA = NULL;
	REFLECTIVELOADER::LPFN_GETPROCADDRESS GetProcAddress = NULL;
	REFLECTIVELOADER::LPFN_VIRTUALALLOC   VirtualAlloc = NULL;
	REFLECTIVELOADER::LPFN_EXITTHREAD     ExitThread = NULL;
	REFLECTIVELOADER::LPFN_EXITTHREAD  RtlExitUserThread = NULL;
	REFLECTIVELOADER::LPFN_NTFLUSHINSTRUCTIONCACHE NtFlushInstructionCache = NULL;

	// STEP 1: process the kernels exports for the functions our loader needs...

	//获得目标进程中Peb
	PPEB Peb = NULL;
#ifdef _WIN64
	Peb = (PPEB)__readgsqword(0x60);
#else
#ifdef _WIN32
	Peb = (PPEB)__readfsdword(0x30);
#else 
#endif
#endif


	ULONG_PTR Ldr = (ULONG_PTR)Peb->Ldr;  //Ldr中有三根链表   当前进程中加载的所有模块      
	PLDR_DATA_TABLE_ENTRY LdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)((PPEB_LDR_DATA)Ldr)->InMemoryOrderModuleList.Flink;

	ULONG_PTR ModuleName = 0;
	ULONG_PTR ModuleBase;
	USHORT ModuleNameLength = 0;
	ULONG_PTR ModuleHashValue = 0;
	ULONG_PTR ImageNtHeaders = NULL;
	ULONG_PTR ImageDataDirectory = 0;
	ULONG_PTR ImageImportDescriptor = NULL;
	ULONG_PTR ImageExportDirectory = NULL;
	ULONG_PTR AddressOfNames = 0;
	ULONG_PTR AddressOfFunctions = 0;
	ULONG_PTR AddressOfNameOrdinals = 0;
	DWORD     NumberOfNames = 0;
	DWORD     HashValue = 0;
	DWORD     IsLoop = 0;
	ULONG_PTR VirtualAddress = 0;
	DWORD     SizeOfHeaders = 0;
	while (LdrDataTableEntry)
	{
		ModuleName = (ULONG_PTR)LdrDataTableEntry->FullDllName.Buffer;   //双字
		ModuleNameLength = LdrDataTableEntry->FullDllName.Length;
		ModuleHashValue = 0;
		do
		{
			ModuleHashValue = ror((DWORD)ModuleHashValue); //Todo
			if (*((BYTE*)ModuleName) >= 'a')   //转换为大写
				ModuleHashValue += *((BYTE*)ModuleName) - 0x20; // 0010 0000 &1101 1111
			else
				ModuleHashValue += *((BYTE*)ModuleName);
			ModuleName++;
		} while (--ModuleNameLength);
		//在目标进程中查询Kernel32
		if ((DWORD)ModuleHashValue == KERNEL32_MODULE_HASH)
		{
			//获得Kerner32.dll的模块地址
			ModuleBase = (ULONG_PTR)LdrDataTableEntry->Reserved2[0];
			ImageNtHeaders = (ModuleBase + ((PIMAGE_DOS_HEADER)ModuleBase)->e_lfanew);
			//有两个成员的结构体目录
			ImageDataDirectory = (UINT_PTR) & ((PIMAGE_NT_HEADERS)ImageNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			//导出表地址
			ImageExportDirectory = (ModuleBase + ((PIMAGE_DATA_DIRECTORY)ImageDataDirectory)->VirtualAddress);
			AddressOfNames = (ModuleBase + ((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfNames);
			AddressOfNameOrdinals = (ModuleBase + ((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfNameOrdinals);
			NumberOfNames = ((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->NumberOfNames;
			IsLoop = 4;
			while (IsLoop > 0 && NumberOfNames > 0)
			{
				HashValue = MakeHashValue((char*)(ModuleBase + DEREFERENCE_32(AddressOfNames)));
				if (HashValue == LOADLIBRARYA_HASH || HashValue == GETPROCADDRESS_HASH || HashValue == VIRTUALALLOC_HASH || HashValue == EXITTHREAD_HSAH)
				{
					AddressOfFunctions = (ModuleBase + ((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfFunctions);
					AddressOfFunctions += (DEREFERENCE_16(AddressOfNameOrdinals) * sizeof(DWORD));
					if (HashValue == LOADLIBRARYA_HASH)
					{
						LoadLibraryA = (REFLECTIVELOADER::LPFN_LOADLIBRARYA)(ModuleBase + DEREFERENCE_32(AddressOfFunctions));
					}
					else if (HashValue == GETPROCADDRESS_HASH)
					{
						GetProcAddress = (REFLECTIVELOADER::LPFN_GETPROCADDRESS)(ModuleBase + DEREFERENCE_32(AddressOfFunctions));
					}
					else if (HashValue == VIRTUALALLOC_HASH)
					{
						VirtualAlloc = (REFLECTIVELOADER::LPFN_VIRTUALALLOC)(ModuleBase + DEREFERENCE_32(AddressOfFunctions));
					}
					else if (HashValue == EXITTHREAD_HSAH)
					{
						ExitThread = (REFLECTIVELOADER::LPFN_EXITTHREAD)(ModuleBase + DEREFERENCE_32(AddressOfFunctions));
					}
					IsLoop--;
				}
				AddressOfNames += sizeof(DWORD);  
				AddressOfNameOrdinals += sizeof(WORD);
				NumberOfNames--;
			}
		}
		else if ((DWORD)ModuleHashValue == NTDLL_MODULE_HASH)
		{
			ModuleBase = (ULONG_PTR)LdrDataTableEntry->Reserved2[0];
			ImageNtHeaders = (ModuleBase + ((PIMAGE_DOS_HEADER)ModuleBase)->e_lfanew);
			ImageDataDirectory = (UINT_PTR) & ((PIMAGE_NT_HEADERS)ImageNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
			ImageExportDirectory = (ModuleBase + ((PIMAGE_DATA_DIRECTORY)ImageDataDirectory)->VirtualAddress);
			AddressOfNames = (ModuleBase + ((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfNames);
			AddressOfNameOrdinals = (ModuleBase + ((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfNameOrdinals);
			NumberOfNames = ((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->NumberOfNames;
			IsLoop = 2;
			while (IsLoop > 0 && NumberOfNames > 0)
			{
				HashValue = MakeHashValue((char*)(ModuleBase + DEREFERENCE_32(AddressOfNames)));
				if (HashValue == NTFLUSHINSTRUCTIONCACHE_HASH || HashValue == RTLEXITUSERTHREAD_HASH)
				{
					AddressOfFunctions = (ModuleBase + ((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfFunctions);
					AddressOfFunctions += (DEREFERENCE_16(AddressOfNameOrdinals) * sizeof(DWORD));
					if (HashValue == NTFLUSHINSTRUCTIONCACHE_HASH)
					{
						NtFlushInstructionCache = (REFLECTIVELOADER::LPFN_NTFLUSHINSTRUCTIONCACHE)(ModuleBase + DEREFERENCE_32(AddressOfFunctions));
					}
					else if (HashValue == RTLEXITUSERTHREAD_HASH)
					{
						RtlExitUserThread = (REFLECTIVELOADER::LPFN_EXITTHREAD)(ModuleBase + DEREFERENCE_32(AddressOfFunctions));
					}
					IsLoop--;
				}
				AddressOfNames += sizeof(DWORD);
				AddressOfNameOrdinals += sizeof(WORD);
				NumberOfNames--;
			}
		}
		if (LoadLibraryA && GetProcAddress && VirtualAlloc && ExitThread && NtFlushInstructionCache)
			break;
		LdrDataTableEntry = (PLDR_DATA_TABLE_ENTRY)DEREFERENCE(LdrDataTableEntry);
	}

	// STEP 2: load our image into a new permanent location in memory...
	ImageNtHeaders = (BufferData + ((PIMAGE_DOS_HEADER)BufferData)->e_lfanew);
	VirtualAddress = (ULONG_PTR)VirtualAlloc(NULL, ((PIMAGE_NT_HEADERS)ImageNtHeaders)->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	SizeOfHeaders = ((PIMAGE_NT_HEADERS)ImageNtHeaders)->OptionalHeader.SizeOfHeaders;

	BYTE* TargetProcessBuffer = (BYTE*)BufferData;     	BYTE* CurentProcessBuffer = (BYTE*)VirtualAddress; 	while (SizeOfHeaders--)
	{
		*(BYTE*)TargetProcessBuffer++ = *(BYTE*)CurentProcessBuffer++;
	}

	// STEP 3.节要使用内存粒度
	ULONG_PTR ImageSectionHeader = ((ULONG_PTR) & ((PIMAGE_NT_HEADERS)ImageNtHeaders)->OptionalHeader + ((PIMAGE_NT_HEADERS)ImageNtHeaders)->FileHeader.SizeOfOptionalHeader);
	WORD NumberOfSections = ((PIMAGE_NT_HEADERS)ImageNtHeaders)->FileHeader.NumberOfSections;

	ULONG_PTR SectionVirtualAddress = 0;
	ULONG_PTR SectionPointerToRawData = 0;
	DWORD     SizeOfRawData = 0;
	while (NumberOfSections--)
	{
		SectionVirtualAddress = (VirtualAddress + ((PIMAGE_SECTION_HEADER)ImageSectionHeader)->VirtualAddress);
		SectionPointerToRawData = (BufferData + ((PIMAGE_SECTION_HEADER)ImageSectionHeader)->PointerToRawData);
		SizeOfRawData = ((PIMAGE_SECTION_HEADER)ImageSectionHeader)->SizeOfRawData;
		while (SizeOfRawData--)
		{
			*(BYTE*)SectionVirtualAddress++ = *(BYTE*)SectionPointerToRawData++;
		}
		ImageSectionHeader += sizeof(IMAGE_SECTION_HEADER);
	}

	// STEP 4: process our images import table...
	ImageDataDirectory = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)ImageNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	ImageImportDescriptor = (VirtualAddress + ((PIMAGE_DATA_DIRECTORY)ImageDataDirectory)->VirtualAddress);

	ULONG_PTR OriginalFirstThunk = 0;
	ULONG_PTR FirstThunk = 0;
	ULONG_PTR ImageImportByName = 0;
	while (((PIMAGE_IMPORT_DESCRIPTOR)ImageImportDescriptor)->Name)
	{
		ModuleBase = (ULONG_PTR)LoadLibraryA((LPCSTR)(VirtualAddress + ((PIMAGE_IMPORT_DESCRIPTOR)ImageImportDescriptor)->Name));
		OriginalFirstThunk = (VirtualAddress + ((PIMAGE_IMPORT_DESCRIPTOR)ImageImportDescriptor)->OriginalFirstThunk);
		FirstThunk = (VirtualAddress + ((PIMAGE_IMPORT_DESCRIPTOR)ImageImportDescriptor)->FirstThunk);
		while (DEREFERENCE(FirstThunk))
		{
			if (OriginalFirstThunk && ((PIMAGE_THUNK_DATA)OriginalFirstThunk)->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				ImageNtHeaders = ModuleBase + ((PIMAGE_DOS_HEADER)ModuleBase)->e_lfanew;
				ImageDataDirectory = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)ImageNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
				ImageExportDirectory = (ModuleBase + ((PIMAGE_DATA_DIRECTORY)ImageDataDirectory)->VirtualAddress);
				AddressOfFunctions = (ModuleBase + ((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfFunctions);
				AddressOfFunctions += ((IMAGE_ORDINAL(((PIMAGE_THUNK_DATA)OriginalFirstThunk)->u1.Ordinal) - ((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->Base) * sizeof(DWORD));
				DEREFERENCE(FirstThunk) = (ModuleBase + DEREFERENCE_32(AddressOfFunctions));
			}
			else
			{
				ImageImportByName = (VirtualAddress + DEREFERENCE(OriginalFirstThunk));
				DEREFERENCE(FirstThunk) = (ULONG_PTR)GetProcAddress((HMODULE)ModuleBase, (LPCSTR)((PIMAGE_IMPORT_BY_NAME)ImageImportByName)->Name);
			}
			FirstThunk += sizeof(ULONG_PTR);
			if (OriginalFirstThunk)
			{
				OriginalFirstThunk += sizeof(ULONG_PTR);
			}
		}
		ImageImportDescriptor += sizeof(IMAGE_IMPORT_DESCRIPTOR);
	}

	// STEP 5: process all of our images relocations...
	ImageNtHeaders = VirtualAddress + ((PIMAGE_DOS_HEADER)VirtualAddress)->e_lfanew;
	ULONG_PTR Diff = VirtualAddress - ((PIMAGE_NT_HEADERS)ImageNtHeaders)->OptionalHeader.ImageBase; 	ImageDataDirectory = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)ImageNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	ULONG_PTR ImageBaseRelocation = NULL;
	ULONG_PTR ImageBaseRelocationItem = 0;
	ULONG_PTR ImageBaseRelocationItemCount = 0;
	if (((PIMAGE_DATA_DIRECTORY)ImageDataDirectory)->Size)
	{
		ImageBaseRelocation = (VirtualAddress + ((PIMAGE_DATA_DIRECTORY)ImageDataDirectory)->VirtualAddress);
		ULONG_PTR AddressItem;
		while (((PIMAGE_BASE_RELOCATION)ImageBaseRelocation)->SizeOfBlock)
		{
			AddressItem = (VirtualAddress + ((PIMAGE_BASE_RELOCATION)ImageBaseRelocation)->VirtualAddress); 			// uiValueB = number of entries in this relocation block
			ImageBaseRelocationItemCount = (((PIMAGE_BASE_RELOCATION)ImageBaseRelocation)->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_BASE_RELOCATION_ITEM);
			ImageBaseRelocationItem = ImageBaseRelocation + sizeof(IMAGE_BASE_RELOCATION);
			while (ImageBaseRelocationItemCount--)
			{
				if (((PIMAGE_BASE_RELOCATION_ITEM)ImageBaseRelocationItem)->Type == IMAGE_REL_BASED_DIR64)
				{
					*(ULONG_PTR*)(AddressItem + ((PIMAGE_BASE_RELOCATION_ITEM)ImageBaseRelocationItem)->Offset) += Diff;
				}
				else if (((PIMAGE_BASE_RELOCATION_ITEM)ImageBaseRelocationItem)->Type == IMAGE_REL_BASED_HIGHLOW)
				{
					*(DWORD*)(AddressItem + ((PIMAGE_BASE_RELOCATION_ITEM)ImageBaseRelocationItem)->Offset) += (DWORD)Diff;
				}
				else if (((PIMAGE_BASE_RELOCATION_ITEM)ImageBaseRelocationItem)->Type == IMAGE_REL_BASED_HIGH)
				{
					*(WORD*)(AddressItem + ((PIMAGE_BASE_RELOCATION_ITEM)ImageBaseRelocationItem)->Offset) += HIWORD(Diff);
				}
				else if (((PIMAGE_BASE_RELOCATION_ITEM)ImageBaseRelocationItem)->Type == IMAGE_REL_BASED_LOW)
				{
					*(WORD*)(AddressItem + ((PIMAGE_BASE_RELOCATION_ITEM)ImageBaseRelocationItem)->Offset) += LOWORD(Diff);
				}
				ImageBaseRelocationItem += sizeof(IMAGE_BASE_RELOCATION_ITEM);
			}
			ImageBaseRelocation = ImageBaseRelocation + ((PIMAGE_BASE_RELOCATION)ImageBaseRelocation)->SizeOfBlock;
		}
	}

	ULONG_PTR AddressOfEntryPoint = (VirtualAddress + ((PIMAGE_NT_HEADERS)ImageNtHeaders)->OptionalHeader.AddressOfEntryPoint);
	NtFlushInstructionCache((HANDLE)-1, NULL, 0);
	((REFLECTIVELOADER::LPFN_DLLMAIN)AddressOfEntryPoint)((HINSTANCE)VirtualAddress, DLL_PROCESS_ATTACH, ParameterData);
	ImageNtHeaders = VirtualAddress + ((PIMAGE_DOS_HEADER)VirtualAddress)->e_lfanew;
	BOOLEAN IsOk;
	ULONG ExitCode;
	do
	{
		ImageDataDirectory = (ULONG_PTR) & ((PIMAGE_NT_HEADERS)ImageNtHeaders)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		if (((PIMAGE_DATA_DIRECTORY)ImageDataDirectory)->Size == 0)
		{
			break;
		}
		ImageExportDirectory = (VirtualAddress + ((PIMAGE_DATA_DIRECTORY)ImageDataDirectory)->VirtualAddress);
		if (((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->NumberOfNames == 0 || ((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->NumberOfFunctions == 0)
		{
			break;
		}
		AddressOfNames = (VirtualAddress + ((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfNames);
		AddressOfNameOrdinals = (VirtualAddress + ((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfNameOrdinals);
		NumberOfNames = ((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->NumberOfNames;
		while (NumberOfNames > 0)
		{
			HashValue = MakeHashValue((char*)(VirtualAddress + DEREFERENCE_32(AddressOfNames)));
			if (HashValue == FunctionHashValue)
			{
				AddressOfFunctions = (VirtualAddress + ((PIMAGE_EXPORT_DIRECTORY)ImageExportDirectory)->AddressOfFunctions);
				AddressOfFunctions += (DEREFERENCE_16(AddressOfNameOrdinals) * sizeof(DWORD));
				AddressOfFunctions = VirtualAddress + DEREFERENCE_32(AddressOfFunctions);
				IsOk = TRUE;
				break;
			}
			AddressOfNames += sizeof(DWORD);
			AddressOfNameOrdinals += sizeof(WORD);
			NumberOfNames--;
		}

		if (IsOk == FALSE)
			break;

		if (!((REFLECTIVELOADER::LPFN_MYFUNCTION)AddressOfFunctions)(UserData, UserDataLength))
			break;

		ExitCode = 0;
	} while (0);

	// We're done, exit thread
	if (RtlExitUserThread)
		RtlExitUserThread(ExitCode);
	else
		ExitThread(ExitCode);
}