#include <iostream>
#include <Windows.h>


int main() {
	
	auto idh = reinterpret_cast<IMAGE_DOS_HEADER*>(GetModuleHandle(L"kernel32.dll"));
	if (idh != NULL) {
		auto inth = reinterpret_cast<IMAGE_NT_HEADERS*>((BYTE*)idh + idh->e_lfanew);
		auto ifh = &inth->FileHeader;
		auto ioh = &inth->OptionalHeader;
		//Parsing IAT
	
		auto* iid = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>((BYTE*)idh + ioh->DataDirectory[1].VirtualAddress);
		auto size_id = ioh->DataDirectory[1].Size / 0x14; // tamanho da struct 0x14, calculo para saber quantas structs tem...
		while (iid->OriginalFirstThunk != NULL) { // O fim dos IID ocorre com um array preenchido com NULLs
			std::cout << "Nome da DLL: " << reinterpret_cast<char*>((BYTE*)idh + iid->Name) << std::endl;
			auto* idt = reinterpret_cast<IMAGE_THUNK_DATA*>((BYTE*)idh + iid->OriginalFirstThunk);
			int num = 1;
			while (idt->u1.AddressOfData != 0) { // O fim do array de idt ocorre com um idt preenchido com 0
				
				std::cout << "Funcao importada no" << num << " - " << reinterpret_cast<char*>((BYTE*)idh + idt->u1.AddressOfData + 2) << std::endl;
				num++;
				idt++;
			}
			iid++;
			std::cout << "\n";
		}
		/*
		for (DWORD i = 0x00; i < size_id; i++) {
			std::cout << "Nome da DLL: " << reinterpret_cast<char*>(iid[i].Name);
			IMAGE_THUNK_DATA* idt = reinterpret_cast<IMAGE_THUNK_DATA*>(iid[i].OriginalFirstThunk);
			while (idt != NULL) {
				static int num = 0;
				std::cout << "Funcao importada no" << num << " - " << idt->u1.ForwarderString << std::endl;
				idt++;
			}

		*/

			/*
		char** itd = reinterpret_cast<char**>(iid[i].OriginalFirstThunk);
		while (itd != NULL) {
			std::cout << "Funcao" << *itd << std::endl;
			itd++;
		}
		*/

	}

	return 0;
}