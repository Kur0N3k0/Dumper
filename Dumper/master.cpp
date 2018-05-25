#include "Master.h"
#include "defines.h"

#include <fstream>
#include <functional>
#include <memory>

#include <psapi.h>
#include <TlHelp32.h>
#include <Shlwapi.h>

namespace Master {
	Process::Process(DWORD pid) {
		this->process.type.pid = pid;
	}
	Process::Process(const char *psname) {
		this->process.type.psname = const_cast<char *>(psname);
	}
	Process::Process(std::string &psname) {
		this->process.type.psname = const_cast<char *>(psname.c_str());
	}

	Process::~Process() {
		for (DWORD i = this->process.nModule - 1; i >= 0; i--) {
			HMODULE hModule = this->process.modules[i].hModule;
			if(hModule != INVALID_HANDLE_VALUE)
				CloseHandle(hModule);
		}
			

		HANDLE hProcess = this->process.hProcess;
		if(hProcess != INVALID_HANDLE_VALUE)
			CloseHandle(hProcess);
	}

	/*
	* @KuroNeko 2018.05.25
	* search for return process handle
	* return #HANDLE#
	*/
	HANDLE _Public Process::getHandle() {
		if (this->process.hProcess != INVALID_HANDLE_VALUE)
			return this->process.hProcess;

		HMODULE hModule[1024];
		DWORD cbneeded;
		if (EnumProcessModules(this->process.hProcess, hModule, sizeof(hModule), &cbneeded)) {
			DWORD nModule = cbneeded / sizeof(HMODULE);
			this->process.modules = new ProcessModule[nModule];
			this->process.nModule = nModule;
			for (int i = 0; i < nModule; i++) {
				char path[MAX_PATH] = { 0, };
				if (GetModuleFileNameEx(this->process.hProcess, hModule[i], path, sizeof(path))) {
					char *file = PathFindFileNameA(path);
					this->process.modules[i].file = file;
					this->process.modules[i].path = PathRemoveFileSpecA(path);
					this->process.modules[i].hModule = hModule[i];

					MODULEINFO minfo;
					if(GetModuleInformation(this->process.hProcess, hModule[i], &minfo, sizeof(minfo)))
						this->process.modules[i].baseaddr = minfo.lpBaseOfDll;
				}
			}
		}

		DWORD item = this->process.type.pid;
		if (item < 65536 && search(item)) {
			return this->process.hProcess;
		}
		else if (search(this->process.type.psname)) {
			return this->process.hProcess;
		}
		return INVALID_HANDLE_VALUE;
	}

	/*
	* @KuroNeko 2018.05.25
	* search with pid, string
	* call by _Public Process::getHandle
	* return #bool#
	*/
	bool _Private Process::search(DWORD pid) {
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		if (hProcess == INVALID_HANDLE_VALUE)
			return false;

		char path[MAX_PATH] = { 0, };
		GetModuleFileNameExA(hProcess, NULL, path, MAX_PATH);
		this->process.exePath = path;
		this->process.hProcess = hProcess;

		return true;
	}
	bool _Private Process::search(std::string psname) {
		HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		PROCESSENTRY32 pe;
		BOOL result = Process32First(hSnap, &pe);
		do {
			if (psname == pe.szExeFile) {
				this->process.type.pid = pe.th32ProcessID;
				return search(pe.th32ProcessID);
			}

			result = Process32Next(hSnap, &pe);
		} while (result);
		return false;
	}

	/*
	* @KuroNeko 2018.05.25
	* Dump2PE with baseaddr.
	* return #bool#
	*/
	bool _Public Process::Dump2PE(const char *output, void *baseaddr) {
		return Dump2PE_internal(output, baseaddr);
	}
	bool _Public Process::Dump2PE(std::string &output, void *baseaddr) {
		return Dump2PE_internal(output.c_str(), baseaddr);
	}
	bool _Public Process::Module2PE(const char *mod, const char *output) {
		DWORD nModule = this->process.nModule;
		ProcessModule *hModules = this->process.modules;
		void *baseaddr = nullptr;

		for (DWORD i = 0; i < nModule; i++) {
			if (hModules[i].file == mod) {
				baseaddr = hModules[i].baseaddr;
				break;
			}
		}
		return Dump2PE_internal(output, baseaddr);
	}
	bool _Private Process::Dump2PE_internal(const char *output, void *baseaddr) {
		HANDLE hProcess = this->process.hProcess;
		if (hProcess == INVALID_HANDLE_VALUE)
			return false;

		std::ofstream file(output, std::ios::binary);

		MEMORY_BASIC_INFORMATION mbi;
		VirtualQueryEx(hProcess, baseaddr, &mbi, sizeof(mbi));

		char *mem = ReadMemory(mbi.BaseAddress, mbi.RegionSize);
		std::unique_ptr<char[]> memory(mem);

		IMAGE_DOS_HEADER &dos = this->process.image.header.dos;
		memcpy(&dos, memory.get(), sizeof(IMAGE_DOS_HEADER));

		IMAGE_NT_HEADERS &nt = this->process.image.header.nt;
		memcpy(&nt, ADDROFFSET(memory.get(), dos.e_lfanew), sizeof(IMAGE_NT_HEADERS));

		ProcessImage &image = this->process.image;
		IMAGE_FILE_HEADER &fileheader = image.header.nt.FileHeader;
		IMAGE_OPTIONAL_HEADER &optional = image.header.nt.OptionalHeader;

		DWORD nSection = fileheader.NumberOfSections;
		DWORD filealign = optional.FileAlignment;
		DWORD offset = dos.e_lfanew + sizeof(IMAGE_NT_HEADERS);

		this->process.image.sections = new IMAGE_SECTION_HEADER[nSection];
		memcpy(
			this->process.image.sections,
			ADDROFFSET(memory.get(), offset),
			nSection * sizeof(IMAGE_SECTION_HEADER)
		);

		/*
		* Parse original exe file for section validation
		*/
		ProcessImage pe;
		bool result = ParseExe(const_cast<char *>(this->process.exePath.c_str()), pe);
		if (result == false)
			return result;

		/*
		* Section validation & repair
		*/
		PIMAGE_SECTION_HEADER sections = this->process.image.sections;
		for (DWORD i = 0; i < nSection; i++) {
			char *result = ReadMemory(ADDROFFSET(baseaddr, sections[i].VirtualAddress), sections[i].SizeOfRawData);
			if (result != nullptr) {
				delete result;
				continue;
			}
			memcpy(&sections[i], &pe.sections[i], sizeof(IMAGE_SECTION_HEADER));
			memcpy(
				ADDROFFSET(memory.get(), offset + i * sizeof(IMAGE_SECTION_HEADER)),
				&sections[i],
				sizeof(IMAGE_SECTION_HEADER)
			);
		}

		auto align = [=](DWORD rawSize, DWORD filealign) {
			DWORD times = rawSize / filealign + 1;
			return filealign * times;
		};

		DWORD prvRawSize = dos.e_lfanew + sizeof(IMAGE_NT_HEADERS);
		prvRawSize += nSection * sizeof(IMAGE_SECTION_HEADER);

		DWORD alignSize = align(prvRawSize, filealign);

		file.write(memory.get(), alignSize);
		file.seekp(sections[0].PointerToRawData);
		memory.reset();

		for (DWORD i = 0; i < nSection; i++) {
			mem = ReadMemory(ADDROFFSET(baseaddr, sections[i].VirtualAddress), sections[i].SizeOfRawData);
			if (mem == nullptr) {
				break;
			}
			std::unique_ptr<char[]> memory(mem);
			file.write(memory.get(), sections[i].SizeOfRawData);
		}

		file.close();
		return true;
	}

	/*
	* @Kuroneko 2018.05.25
	* ReadProcessMemory wrapper
	* return #char *#
	*/
	char * _Private Process::ReadMemory(void *addr, SIZE_T size) {
		return ReadMemroy_internal(addr, size);
	}
	char * _Private Process::ReadMemory(void *addr, MEMORY_BASIC_INFORMATION &mbi) {
		return ReadMemroy_internal(addr, mbi.RegionSize);
	}
	char * _Private Process::ReadMemroy_internal(void *addr, SIZE_T size) {
		HANDLE hProcess = this->process.hProcess;
		if (hProcess == INVALID_HANDLE_VALUE)
			return nullptr;

		MEMORY_BASIC_INFORMATION mbi;
		VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi));

		DWORD old = (DWORD)-1;
		if (mbi.AllocationProtect == PAGE_EXECUTE_WRITECOPY) {
			BOOL result = VirtualProtectEx(hProcess, addr, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &old);
			if (result == FALSE)
				return nullptr;
		}

		char *memory = nullptr;
		try {
			memory = new char[size + 1];
			SIZE_T readbytes;
			BOOL result = ReadProcessMemory(hProcess, addr, memory, size, &readbytes);
			if (result == FALSE) {
				delete memory;
				return nullptr;
			}
		}
		catch (std::bad_alloc except) {
			return nullptr;
		}

		if (old != (DWORD)-1)
			VirtualProtectEx(hProcess, addr, mbi.RegionSize, old, &old);

		return memory;
	}

	bool _Private Process::ParseExe(char *path, ProcessImage &pe) {
		std::ifstream file(path, std::ios::binary);

		IMAGE_DOS_HEADER &dos = pe.header.dos;
		IMAGE_NT_HEADERS &nt = pe.header.nt;

		file.read(reinterpret_cast<char *>(&dos), sizeof(dos));
		file.seekg(dos.e_lfanew);
		file.read(reinterpret_cast<char *>(&nt), sizeof(nt));
		file.seekg(dos.e_lfanew + sizeof(nt));

		DWORD nSection = nt.FileHeader.NumberOfSections;
		pe.sections = new IMAGE_SECTION_HEADER[nSection];
		file.read(reinterpret_cast<char *>(pe.sections), nSection * sizeof(IMAGE_SECTION_HEADER));
		return true;
	}
}