# Dumper
Process Dump

## Classes
- Master::Process
  - The Process class in the master namespace contains functions for dumping exe and dll files.
  ```c++
  HANDLE getHandle();
  bool Dump2PE(const char *output, void *baseaddr);
  bool Dump2PE(std::string &output, void *baseaddr);
  bool Module2PE(const char *mod, const char *output);
  ```
  - When the getHandle() function is called, the module information of the corresponding process is obtained.
    For this reason, you must call the getHandle() function first.
  - The Dump2PE() function should create a dump binary storage path and base address to be dumped.
  - The Module2PE() function must create a module name in the process to be dumped and a storage path to be dumped.
  - Example
  ```c++
  Master::Process process("calc.exe");
  HANDLE hProcess = process.getHandle();
  if(!hProcess)
    return 0;
  process.Dump2PE("calc.exe", (void *)0x00400000);
  process.Module2PE("kernel32.dll", "kernel32.dll");
  ```

## Structures
- ProcessImageHeader
- ProcessImage
- ProcessModule
- Process
  ```c++
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
  ```
  - Process structure can receive and set information of PE image and modules.
  - Example
  ```c++
  ...
  HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (!hProcess)
    return false;

  char path[MAX_PATH] = { 0, };
  GetModuleFileNameExA(hProcess, NULL, path, MAX_PATH);
  this->process.exePath = path;
  this->process.hProcess = hProcess;
  ...
  ```
