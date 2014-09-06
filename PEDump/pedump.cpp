#include <Windows.h>
#include <stdio.h>

DWORD RVA_to_physical(DWORD RVA, IMAGE_SECTION_HEADER* sections, int num_sections){
	for (size_t i = 0; i < num_sections; i++)
	{
		if (RVA >= sections[i].VirtualAddress && RVA < sections[i].VirtualAddress + sections[i].SizeOfRawData)
			return sections[i].PointerToRawData + (RVA - sections[i].VirtualAddress);
	}
	return -1;
}

int main(int argc, const char* argv[]){
	printf("pedump by E.Sandberg\n");
	if (argc != 2){
		printf("usage: pedump <file>\n");
		return 1;
	}
	FILE *f = fopen(argv[1], "rb");
	fseek(f, 0, SEEK_END);
	DWORD fileLen = ftell(f);
	fseek(f, 0, SEEK_SET);
	char* peFile = (char*)malloc(fileLen);
	fread(peFile, fileLen, 1, f);
	fclose(f);

	IMAGE_DOS_HEADER dosHeader = *((IMAGE_DOS_HEADER*)peFile);
	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("Not a PE file, missing DOS magic MZ\n");
		return 1;
	}
	IMAGE_NT_HEADERS ntHeaders = *((IMAGE_NT_HEADERS*)(peFile + dosHeader.e_lfanew));
	if (ntHeaders.Signature != IMAGE_NT_SIGNATURE){
		printf("Not a PE file, PE signature is wrong\n");
		return 1;
	}
	IMAGE_SECTION_HEADER *sections = (IMAGE_SECTION_HEADER*)(peFile + dosHeader.e_lfanew + sizeof(IMAGE_NT_HEADERS));
	printf("SECTIONS:\n");
	for (size_t i = 0; i < ntHeaders.FileHeader.NumberOfSections; i++)
	{
		printf("\t%d. %s\n", i, sections[i].Name);
	}

	DWORD exportDirectoryOffset = RVA_to_physical(ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, sections, ntHeaders.FileHeader.NumberOfSections);
	if (exportDirectoryOffset != -1){
		IMAGE_EXPORT_DIRECTORY exportDirectory = *(IMAGE_EXPORT_DIRECTORY*)(peFile + exportDirectoryOffset);

		DWORD nameOffset = RVA_to_physical(exportDirectory.Name, sections, ntHeaders.FileHeader.NumberOfSections);
		if (nameOffset != -1 && exportDirectory.NumberOfNames > 0){
			printf("EXPORTS in %s:\n", (char*)(peFile + nameOffset));
			DWORD nameTableOffset = RVA_to_physical(exportDirectory.AddressOfNames, sections, ntHeaders.FileHeader.NumberOfSections);
			if (nameTableOffset != -1){
				unsigned int* nameTable = (unsigned int*)(peFile + nameTableOffset);
				for (size_t i = 0; i < exportDirectory.NumberOfNames; i++)
				{
					DWORD actualNameOffset = RVA_to_physical(nameTable[i], sections, ntHeaders.FileHeader.NumberOfSections);
					if (actualNameOffset != -1){
						char* name = (char*)(peFile + actualNameOffset);
						printf("\t%s\n", name);
					}
				}
			}
		}
	}

	DWORD importDirectoryOffset = RVA_to_physical(ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, sections, ntHeaders.FileHeader.NumberOfSections);
	if (importDirectoryOffset != -1){
		printf("IMPORTS:\n");
		IMAGE_IMPORT_DESCRIPTOR *import_descriptors = (IMAGE_IMPORT_DESCRIPTOR*)(peFile + importDirectoryOffset);
		for (size_t i = 0; ; i++)
		{
			if (import_descriptors[i].Characteristics == 0 &&
				import_descriptors[i].FirstThunk == 0 &&
				import_descriptors[i].ForwarderChain == 0 &&
				import_descriptors[i].Name == 0 &&
				import_descriptors[i].OriginalFirstThunk == 0 &&
				import_descriptors[i].TimeDateStamp == 0)
				break;
			DWORD name_offset = RVA_to_physical(import_descriptors[i].Name, sections, ntHeaders.FileHeader.NumberOfSections);
			if (name_offset != -1){
				printf("\t%d. %s:\n", i, (char*)(peFile + name_offset));
				DWORD iat_offset = RVA_to_physical(import_descriptors[i].OriginalFirstThunk, sections, ntHeaders.FileHeader.NumberOfSections);
				if (iat_offset != -1){
					IMAGE_THUNK_DATA *iat = (IMAGE_THUNK_DATA*)(peFile + iat_offset);
					for (size_t n = 0;; n++)
					{
						if (iat[n].u1.AddressOfData == 0)
							break;
						if (iat[n].u1.AddressOfData >> 31 == 0){
							DWORD import_name_offset = RVA_to_physical(iat[n].u1.AddressOfData, sections, ntHeaders.FileHeader.NumberOfSections);
							if (import_name_offset != -1){
								IMAGE_IMPORT_BY_NAME* import_by_name = (IMAGE_IMPORT_BY_NAME*)(peFile + import_name_offset);
								printf("\t\t%s\n", (char*)import_by_name->Name);
							}
						}
					}
				}
			}			
		}
	}
	free(peFile);
	return 0;
}