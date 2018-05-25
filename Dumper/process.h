#pragma once

#include <string>
#include <Windows.h>

#pragma pack(push, 1)
typedef struct _ProcessImageHeader {
	IMAGE_DOS_HEADER dos;
	IMAGE_NT_HEADERS nt;
} ProcessImageHeader;

typedef struct _ProcessImage {
	using PIMAGE_SECTION = void *;
	ProcessImageHeader header;
	PIMAGE_SECTION_HEADER sections = nullptr;
	PIMAGE_SECTION section;
} ProcessImage;

typedef struct _ProcessModule {
	std::string file;
	std::string path;
	HMODULE hModule;
	void *baseaddr = nullptr;
} ProcessModule;

typedef struct _Process {
	union {
		DWORD pid;
		char *psname;
	} type;
	HANDLE hProcess = NULL;
	ProcessImage image;
	ProcessModule *modules = nullptr;
	DWORD nModule;
	std::string exePath;
} Process;
#pragma pack(pop)