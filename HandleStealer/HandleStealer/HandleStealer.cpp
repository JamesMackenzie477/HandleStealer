#include <iostream>
#include <Windows.h>
#include <Winternl.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <string>

using namespace std;

// defines the query handle information value
#define SystemHandleInformation (SYSTEM_INFORMATION_CLASS)0x10
// defines the length mismatch error
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

// structure that contains handle information
typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, *PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

// structure that cointains the array of handles returned from the system query
typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

// sets the debug flag in the access token
BOOLEAN EnableDebugPrivilege()
{
	// stores the token handle
	HANDLE hToken;
	// opens our access token
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		// stores the privilege to be applied to the acces token
		TOKEN_PRIVILEGES tp;
		// stores the luid of the privilege
		LUID luid;
		// lookups the luid of the privilege
		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
		{
			// sets the privilege count
			tp.PrivilegeCount = 1;
			// sets the luid of the privilege
			tp.Privileges[0].Luid = luid;
			// sets the privilege to enables
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			// adjusts the privilege
			if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
			{
				// returns true
				return TRUE;
			}
		}
	}
	// else we return false
	return FALSE;
}

// returns the process id for the given image name
DWORD FindProcess(string sImage)
{
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	// validates the handle
	if (hSnapshot != INVALID_HANDLE_VALUE)
	{
		// stores the process information
		PROCESSENTRY32 ProcessInfo;
		// sets the structure size
		ProcessInfo.dwSize = sizeof(PROCESSENTRY32);
		// gets the first process
		if (Process32First(hSnapshot, &ProcessInfo))
		{
			// gets the information of the next process
			do
			{
				// checks the process name
				if (strcmp(ProcessInfo.szExeFile, sImage.c_str()) == 0)
				{
					// returns the pid
					return ProcessInfo.th32ProcessID;
				}
			} while (Process32Next(hSnapshot, &ProcessInfo));
		}
	}
	// else we return null
	return NULL;
}

// queries the system a returns a list of handles open to the given process id with the desired access
PSYSTEM_HANDLE_INFORMATION SystemQueryHandles(DWORD ProcessId, DWORD RequiredAccess)
{
	// allocates a buffer to store the retrieved handle information
	PSYSTEM_HANDLE_INFORMATION pHandles = (PSYSTEM_HANDLE_INFORMATION)malloc(10000);
	// stores the return length
	ULONG uLength = 10000;
	// zeros out the buffer
	ZeroMemory(pHandles, 10000);
	// queries all the handles on the system
	while (NtQuerySystemInformation(SystemHandleInformation, pHandles, uLength, &uLength) == STATUS_INFO_LENGTH_MISMATCH)
	{
		// reallocates the buffer to the correct size
		pHandles = (PSYSTEM_HANDLE_INFORMATION)realloc(pHandles, uLength);
		// zeros out the buffer
		ZeroMemory(pHandles, uLength);
	}
	// creates a buffer to store the found handles
	PSYSTEM_HANDLE_INFORMATION pFoundHandles = (PSYSTEM_HANDLE_INFORMATION)malloc(uLength);
	// zeros out the buffer
	ZeroMemory(pFoundHandles, uLength);
	// iterates through system handles
	for (int i = 0; i < pHandles->HandleCount; i++)
	{
		// checks the handles access rights
		if ((pHandles->Handles[i].GrantedAccess & RequiredAccess) == RequiredAccess)
		{
			// opens the process that contains the handle with duplicate handle privileges
			HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pHandles->Handles[i].ProcessId);
			// validates the handle
			if (hProcess != INVALID_HANDLE_VALUE)
			{
				// stores the duplicate handle
				HANDLE hHandle;
				// duplicates the handle
				if (DuplicateHandle(hProcess, (HANDLE)pHandles->Handles[i].Handle, GetCurrentProcess(), &hHandle, PROCESS_QUERY_LIMITED_INFORMATION, FALSE, NULL))
				{
					// gets the process id of the handle
					DWORD ProcId = GetProcessId(hHandle);
					// checks the process id
					if (GetProcessId(hHandle) == ProcessId)
					{
						// adds the handle to the buffer
						pFoundHandles->Handles[pFoundHandles->HandleCount] = pHandles->Handles[i];
						// increments the handle count
						pFoundHandles->HandleCount++;
					}
					// closes the duplicate handle
					CloseHandle(hHandle);
				}
				// closes the process handle
				CloseHandle(hProcess);
			}
		}
	}
	// frees the handles buffer
	free(pHandles);
	// returns the list of handles
	return pFoundHandles;
}

// makes the given handle in the given process inheritable via shell code injection
BOOLEAN MakeHandleInheritable(HANDLE hProcess, HANDLE hTarget)
{
	// stores the result
	BOOLEAN Status = FALSE;
	// stores the shell code to make the handle inheritable
	byte ShellCode[] = { 0x48, 0x83, 0xEC, 0x30, 0x41, 0xB8, 0x01, 0x00, 0x00, 0x00,
		0xBA, 0x01, 0x00, 0x00, 0x00, 0x48, 0xB9, 0xAA, 0xAA, 0xAA,
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x48, 0xB8, 0xAA, 0xAA, 0xAA,
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xFF, 0xD0, 0x48, 0xB9, 0xAA,
		0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x88, 0x01, 0x48,
		0x83, 0xC4, 0x30, 0x48, 0x31, 0xC0, 0xC3, 0x90 };
	// allocates memory for the shell code in the target program
	PVOID pShellCode = VirtualAllocEx(hProcess, NULL, sizeof(ShellCode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	// validates the address
	if (pShellCode)
	{
		// stores the address of the status byte
		PVOID pStatus = (PVOID)((DWORD64)pShellCode + sizeof(ShellCode) - 1);
		// adds the handle to the shellcode
		*(DWORD64*)(ShellCode + 17) = (DWORD64)hTarget;
		// adds set handle information address to the shellcode
		*(DWORD64*)(ShellCode + 27) = (DWORD64)SetHandleInformation;
		// adds the address that is set to true if it is successful
		*(DWORD64*)(ShellCode + 39) = (DWORD64)pStatus;
		// writes shell code buffer to the base address
		if (WriteProcessMemory(hProcess, pShellCode, ShellCode, sizeof(ShellCode), NULL))
		{
			// creates a thread to execute the shell code
			if (HANDLE hThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pShellCode, NULL, NULL, NULL))
			{
				// waits for a result
				do { ReadProcessMemory(hProcess, pStatus, &Status, sizeof(Status), NULL); } while (Status == 0x90);
			}
		}
		// deallocates the shell code memory
		VirtualFreeEx(hProcess, pShellCode, sizeof(ShellCode), MEM_RELEASE);
	}
	// returns the status
	return Status;
}

// creates a child process of the given handle
BOOLEAN CreateChildProcess(HANDLE hProcess, string sArgs)
{
	// stores the size of the attributes
	SIZE_T AttributesSize = 100;
	// allocates a buffer
	PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)malloc(AttributesSize);
	// gets the attribute list size
	if (InitializeProcThreadAttributeList(pAttributeList, 1, 0, &AttributesSize))
	{
		// adds the process handle to the attribute list
		if (UpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hProcess, sizeof(HANDLE), NULL, NULL))
		{
			// creates a startup info structure
			STARTUPINFOEX StartupInfo;
			// creates a process info structure
			PROCESS_INFORMATION ProcessInfo;
			// zeroes out the structure
			ZeroMemory(&StartupInfo, sizeof(STARTUPINFO));
			// zeroes out the structure
			ZeroMemory(&ProcessInfo, sizeof(PROCESS_INFORMATION));
			// sets the structure size
			StartupInfo.StartupInfo.cb = sizeof(STARTUPINFO);
			// adds the attribute list
			StartupInfo.lpAttributeList = pAttributeList;
			// creates a child process
			if (CreateProcessA(NULL, (LPSTR)sArgs.c_str(), NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE, NULL, NULL, &StartupInfo.StartupInfo, &ProcessInfo))
			{
				// returns true
				return TRUE;
			}
		}
	}
	// else we return false
	return FALSE;
}

// the main entry of the program
int main(int argc, char *argv[])
{
	// if there's only one argument
	if (argc == 1)
	{
		// give our program the debug privilege
		if (EnableDebugPrivilege())
		{
			// finds the process
			if (DWORD ProcessId = FindProcess("ironsight.exe"))
			{
				// notifies user
				cout << "[+] Program elevated to debugger" << endl;
				// gets a list of open handles to the process id
				PSYSTEM_HANDLE_INFORMATION pHandles = SystemQueryHandles(ProcessId, 0);
				// notifies user
				cout << "[+] Found " << pHandles->HandleCount << " handle(s) for process: " << ProcessId << endl;
				// iterates through the handles
				for (int i = 0; i < pHandles->HandleCount; i++)
				{
					// notifies user
					cout << "[+] Attempting exploit on process: " << pHandles->Handles[i].ProcessId << endl;
					// opens a handle to the process
					HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_CREATE_PROCESS | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, pHandles->Handles[i].ProcessId);
					// validates the handle
					if (hProcess != INVALID_HANDLE_VALUE)
					{
						// notifies user
						cout << "[+] Successfully opened a PROCESS_ALL_ACCESS handle" << endl;
						// sets the handle as inheritable
						if (MakeHandleInheritable(hProcess, (HANDLE)pHandles->Handles[i].Handle))
						{
							// notifies user
							cout << "[+] Successfully made the target handle inheritable" << endl;
							// stores the path of the current process
							CHAR ProcessPath[MAX_PATH];
							// gets the path of the current process
							GetModuleFileName(NULL, ProcessPath, MAX_PATH);
							// creates a child process of the open process
							if (CreateChildProcess(hProcess, (string)ProcessPath + " " + to_string(pHandles->Handles[i].Handle) + " child"))
							{
								// notifies user
								cout << "[+] Successfully created child process" << endl;
								// exits the process
								return 0;
								// breaks out of the loop
								break;
							}
							else
							{
								// notifies user
								cout << "[-] Could not create a child process" << endl;
							}
						}
						else
						{
							// notifies user
							cout << "[-] Could not make the target handle inheritable" << endl;
						}
					}
					else
					{
						// notifies user
						cout << "[-] Could not open a handle to the process" << endl;
					}
				}
			}
			else
			{
				// notifies user
				cout << "[-] Process not found" << endl;
			}
		}
	}
	else if (argc == 3)
	{
		// if we are a child process
		if (strcmp(argv[2], "child") == 0)
		{
			// stores the path of the current process
			CHAR ProcessPath[MAX_PATH];
			// gets the path of the current process
			GetModuleFileName(NULL, ProcessPath, MAX_PATH);
			// creates a granchild process
			if (CreateChildProcess(GetCurrentProcess(), (string)ProcessPath + " " + (string)argv[1] + " granchild"))
			{
				// notifies user
				cout << "[+] Successfully created a granchild process" << endl;
				// exits the process
				return 0;
			}
			else
			{
				// notifies user
				cout << "[-] Could not create a granchild process" << endl;
			}
		}
		else if (strcmp(argv[2], "granchild") == 0)
		{
			// casts the argument to a handle
			HANDLE hProcess = (HANDLE)stoi(argv[1]);
			// stores the handle information
			DWORD HandleInfo;
			// checks if the handle is valid
			if (GetHandleInformation(hProcess, &HandleInfo))
			{
				// notifies user
				cout << "[+] Obtained valid handle: 0x" << hex << stoi(argv[1]) << endl;
				// CALL MANUAL MAPPER HERE
				// ManualMap(hProcess, "hack.dll");
			}
			else
			{
				// notifies user
				cout << "[-] The handle obtained is invalid" << endl;
			}
		}
	}
	// waits to exit
	cin.get();
	// returns to kernel
	return 0;
}

// Just me, myself and I...
// Each WinApi function that is added to the shell code subtract the base address of their DLL then add the result to the base of the target's DLL,
// this will stop any errors if their image has benn rebased.
// Make SystemQueryHandles return a linked list instead, this will save on memory space.
// The entries will contain a struct for the next entry, an open handle to the target process and the target handle
// Get the shell code to call CreateProcessA with the given parameters.
// Allocate the process and thread info structures in the target and set the size.
// Also later we can try Kernel handle elevation via DKOM and a vulnerable driver, such as CPU-Z or VMWare.
// We can also use the driver to set g_CiEnabled to false to enable non-signed drivers to load
// Also manual mapping and RunPE should be looked into.
// Same with Kernel dumping.

// THIS COULD BE DONE WITH DLL INJECTION!
// By loading the DLL via CreateRemoteThread, and then using CreateRemoteThread to call a function in the DLL with a structure of needed parameters which will do what we're doing with the shell code.
// But I want to use shell code...