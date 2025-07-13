#pragma once

#include "Structs.h"
#include "Hashing.h"

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes(p,n,a,r,s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);   \
    (p)->RootDirectory = r;                    \
    (p)->Attributes = a;                       \
    (p)->ObjectName = n;                       \
    (p)->SecurityDescriptor = s;               \
    (p)->SecurityQualityOfService = NULL;      \
}
#endif


HMODULE GetMH(IN DWORD hash)
{

	PPEB pPeb = (PEB*)(__readgsqword(0x60));

	PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)(pPeb->Ldr);
	PLDR_DATA_TABLE_ENTRY pDte = (PLDR_DATA_TABLE_ENTRY)(pLdr->InMemoryOrderModuleList.Flink);

	while (pDte) {

		if (pDte->FullDllName.Length != NULL) {

			CHAR UpperCaseDllName[MAX_PATH];

			DWORD i = 0;
			while (pDte->FullDllName.Buffer[i]) {
				UpperCaseDllName[i] = (CHAR)toupper(pDte->FullDllName.Buffer[i]);
				i++;
			}
			UpperCaseDllName[i] = '\0';

			if (HASHA(UpperCaseDllName) == hash) {
				wprintf(L"[+] Found Dll \"%s\" \n", pDte->FullDllName.Buffer);
				return (HMODULE)(pDte->InInitializationOrderLinks.Flink);
			}
		}
		else break;

		pDte = *(PLDR_DATA_TABLE_ENTRY*)(pDte);
	}

	return NULL;
}


PVOID GetPA(IN HMODULE hModule, IN DWORD hash)
{
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

		if (hash == HASHA(pFunctionName)) {
			return (PVOID)(pBase + FunctionAddressArray[FunctionOrdinalArray[i]]);;
		}
	}

	return NULL;
}
