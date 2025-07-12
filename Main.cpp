#include "NtSignatures.h"
#include "Structs.h"

#ifndef STRUCTS
#include <winternl.h>
#endif // !STRUCTS

#define CONTAINING_RECORD(address, type, field) \
    ((type *)((PCHAR)(address) - (ULONG_PTR)(&((type *)0)->field)))



BOOL IsStringEqual(IN LPCWSTR Str1, IN LPCWSTR Str2) {

	WCHAR	lStr1[MAX_PATH],
		lStr2[MAX_PATH];

	int		len1 = lstrlenW(Str1),
		len2 = lstrlenW(Str2);

	int		i = 0,
		j = 0;

	if (len1 >= MAX_PATH || len2 >= MAX_PATH)
		return FALSE;

	for (i = 0; i < len1; i++) {
		lStr1[i] = (WCHAR)tolower(Str1[i]);
	}
	lStr1[i++] = L'\0'; // null terminating

	for (j = 0; j < len2; j++) {
		lStr2[j] = (WCHAR)tolower(Str2[j]);
	}
	lStr2[j++] = L'\0'; // null terminating

	if (lstrcmpiW(lStr1, lStr2) == 0)
		return TRUE;

	return FALSE;
}



HMODULE GetMH(IN LPCWSTR szModuleName) {

#ifdef _WIN64 // if compiling as x64
	PPEB					pPeb = (PEB*)(__readgsqword(0x60));
#elif _WIN32 // if compiling as x32
	PPEB					pPeb = (PEB*)(__readfsdword(0x30));
#endif

	PPEB_LDR_DATA			pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
	PLDR_DATA_TABLE_ENTRY	pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {

		if (pDte->FullDllName.Length != NULL) {

			if (IsStringEqual(pDte->FullDllName.Buffer, szModuleName)) {
				wprintf(L"[+] Found Dll \"%s\" \n", pDte->FullDllName.Buffer);
#ifdef STRUCTS
				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
#else
				return (HMODULE)pDte->Reserved2[0];
#endif // STRUCTS

			}
		}
		else break;

		// next element in the linked list
		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
	}

	return NULL;
}


PVOID GetPA(IN HMODULE hModule, IN LPCSTR lpApiName) {
	PBYTE pBase = (PBYTE)hModule;

	PIMAGE_DOS_HEADER	pImgDosHdr = (PIMAGE_DOS_HEADER)pBase;
	if (pImgDosHdr->e_magic != IMAGE_DOS_SIGNATURE)
		return NULL;

	PIMAGE_NT_HEADERS	pImgNtHdrs = (PIMAGE_NT_HEADERS)(pBase + pImgDosHdr->e_lfanew);
	if (pImgNtHdrs->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	IMAGE_OPTIONAL_HEADER	ImgOptHdr = pImgNtHdrs->OptionalHeader;
	PIMAGE_EXPORT_DIRECTORY pImgExportDir = (PIMAGE_EXPORT_DIRECTORY)(pBase + ImgOptHdr.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	PDWORD FunctionNameArray = (PDWORD)(pBase + pImgExportDir->AddressOfNames);
	PDWORD FunctionAddressArray = (PDWORD)(pBase + pImgExportDir->AddressOfFunctions);
	PWORD  FunctionOrdinalArray = (PWORD)(pBase + pImgExportDir->AddressOfNameOrdinals);


	for (DWORD i = 0; i < pImgExportDir->NumberOfFunctions; i++) {
		CHAR* pFunctionName = (CHAR*)(pBase + FunctionNameArray[i]);

		if (strcmp(lpApiName, pFunctionName) == 0) {
			return (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);;
		}
	}

	return NULL;
}


int main() {

	HANDLE hProc = GetCurrentProcess();
	HMODULE hMod = GetMH(L"NTDLL.DLL");
	unsigned char shellcode[] =
		"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa";
	NtAllocateVirtualMemory ntAlloc = (NtAllocateVirtualMemory)GetPA(hMod, "NtWriteVirtualMemory");
	NtWriteVirtualMemory ntWrite = (NtWriteVirtualMemory)GetPA(hMod, "NtWriteVirtualMemory");

	ntAlloc(hProc, 0, 0, (PSIZE_T)sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	ntWrite(hProc, 0, shellcode, NULL, NULL);

	printf("[#] Press <Enter> To Quit ... ");

	getchar();

	return 0;

}