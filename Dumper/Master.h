#pragma once

#include "process.h"

namespace Master{
	class Process {
	public:
		Process(DWORD pid);
		Process(const char *psname);
		Process(std::string &psname);
		~Process();

		HANDLE getHandle();
		bool Dump2PE(const char *output, void *baseaddr);
		bool Dump2PE(std::string &output, void *baseaddr);
		bool Module2PE(const char *mod, const char *output);

	private:
		::Process process;

		bool search(DWORD pid);
		bool search(std::string psname);

		bool Dump2PE_internal(const char *output, void *baseaddr);
		char *ReadMemory(void *addr, SIZE_T size);
		char *ReadMemory(void *addr, MEMORY_BASIC_INFORMATION &mbi);
		char *ReadMemroy_internal(void *addr, SIZE_T size);
		bool ParseExe(char *path, ProcessImage &pe);

		inline auto ADDROFFSET(LPVOID addr, DWORD offset) {
			return (void *)((DWORD)addr + offset);
		};
	};
};