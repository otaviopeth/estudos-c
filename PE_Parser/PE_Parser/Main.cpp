#include <Windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <sstream>


bool PeCheck(IMAGE_DOS_HEADER*);
IMAGE_DOS_HEADER* FileLoader();

int main() {
	IMAGE_DOS_HEADER* pe = (IMAGE_DOS_HEADER*) FileLoader();
	if (pe) {
		std::ofstream oWriter;
		std::string logName;

		std::cout << "Arquivo PE detectado!\nDigite um nome para o arquivo de log: ";
		std::getline(std::cin, logName);
		oWriter.open(logName, std::ios::binary);
		if (oWriter.is_open()) {
			IMAGE_NT_HEADERS* peNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>((BYTE*)pe + *(LONG*)((BYTE*)pe + 0x3c));
			IMAGE_FILE_HEADER* peFileHeader = &peNtHeader->FileHeader;
			IMAGE_OPTIONAL_HEADER* peOptHeader = &peNtHeader->OptionalHeader;
		
		}
		else {
			printf("Erro de gravação: %d", oWriter.rdstate());
			oWriter.close();
		}
		oWriter.close();
	}
	return 0;
}

bool PeCheck(IMAGE_DOS_HEADER* peName){
	if (peName->e_magic == '\x4D\x5A') {
		return true;
	}
	return false;
}

IMAGE_DOS_HEADER* FileLoader()
{
	std::string	peName;
	std::cout << "Digite o nome e extensão do arquivo [Ex: nome.exe]: ";
	std::getline(std::cin, peName);
	std::ifstream iReader;
	iReader.open(peName, std::ios::ate | std::ios::binary);
	if (iReader.is_open()) {
		int size = iReader.tellg();
		IMAGE_DOS_HEADER* peInMemory = reinterpret_cast<IMAGE_DOS_HEADER*>(VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
		iReader.seekg(std::ios::beg);
		iReader.read(reinterpret_cast<char*>(peInMemory), size);
		if (PeCheck(peInMemory)) {
			iReader.close();
			return peInMemory;
		}
		else {
			printf("Arquivo não é um executável");
			iReader.close();
			return nullptr;
		}

	}
	else {
		printf("Erro de leitura: %d", iReader.rdstate());
		iReader.close();
		return nullptr;
	}
}
