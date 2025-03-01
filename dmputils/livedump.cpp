#include "livedump.h"

#define CONTROL_LIVE_KERNEL_DUMP (SYSDBG_COMMAND)37

bool changeDebugPrivilege(bool enable)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    // Open the current process token
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cout << "Error: Failed to open process token" << std::endl;
        return false;
    }

    // Get the LUID for the debug privilege
    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        std::cout << "Error: Failed to lookup privilege value" << std::endl;
        CloseHandle(hToken);
        return false;
    }

    // Set up the token privileges structure
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

    // Adjust the token privileges
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        std::cout << "Error: Failed to adjust token privileges" << std::endl;
        CloseHandle(hToken);
        return false;
    }

    // Check if the privilege was actually adjusted
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        std::cout << "Error: The token does not have the specified privilege" << std::endl;
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

bool checkWinVer()
{
    typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll)
        return false;

    RtlGetVersionPtr RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(hNtdll, "RtlGetVersion");
    if (!RtlGetVersion)
        return false;

    RTL_OSVERSIONINFOW osvi = { 0 };
    osvi.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);
    if (RtlGetVersion(&osvi) != 0) // STATUS_SUCCESS = 0
        return false;

    // Check for Windows 11 (Windows 11 is Windows 10 with build number 22000 or higher)
    if (osvi.dwMajorVersion < 10 || 
        (osvi.dwMajorVersion == 10 && osvi.dwBuildNumber < 22621)) {
        std::cout << "Error: This feature requires Windows 11 build 22621 or later" << std::endl;
        return false;
    }
    
    return true;
}

bool doLiveDump(const std::string& dumpFolder)
{
	if (!checkWinVer())
	{
		return false;
	}

	using fnNtSystemDebugControl = decltype(&NtSystemDebugControl);
	fnNtSystemDebugControl NtSystemDebugControl = (fnNtSystemDebugControl)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSystemDebugControl");
	if (!NtSystemDebugControl)
	{
		std::cout << "Error: Failed to get NtSystemDebugControl address" << std::endl;
		return false;
	}

	// Enable debug privilege
	if (!changeDebugPrivilege(true))
	{
		std::cout << "Error: Failed to enable debug privilege" << std::endl;
		return false;
	}
	
    // Check if the dump folder exists
    DWORD fileAttributes = GetFileAttributesA(dumpFolder.c_str());
    if (fileAttributes == INVALID_FILE_ATTRIBUTES || !(fileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
        std::cout << "Error: Dump folder does not exist: " << dumpFolder << std::endl;
        return false;
    }
	
    SYSDBG_LIVEDUMP_CONTROL_FLAGS flags = { 0 };
    SYSDBG_LIVEDUMP_CONTROL_ADDPAGES pages = {0};

	flags.UseDumpStorageStack = 1;

    // No hypervisor pages or usermode pages for now.
    
    std::string finalDumpPath = dumpFolder;

	// Append a backslash if it's not there
	if (finalDumpPath.back() != '\\')
		finalDumpPath += "\\";

	// Get the date time as a string
	SYSTEMTIME st;
	GetSystemTime(&st);

	// Format the date time as a string in dd_mm_yyyy_hh_mm format
	char dateTime[100];
	sprintf_s(dateTime, "%02d_%02d_%04d_%02d_%02d", 
		st.wDay, st.wMonth, st.wYear, 
		st.wHour, st.wMinute);

	// Append the date time to the dump path
	finalDumpPath += dateTime;
	finalDumpPath += ".dmp";

	// Create the dump file
	HANDLE hFile = CreateFileA(finalDumpPath.c_str(), GENERIC_WRITE | GENERIC_READ, FILE_SHARE_NONE, NULL, CREATE_ALWAYS, FILE_FLAG_WRITE_THROUGH | FILE_FLAG_NO_BUFFERING, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		std::cout << "Error: Failed to create dump file: " << finalDumpPath << std::endl;
		return false;
	}
	
	NTSTATUS status;
    SYSDBG_LIVEDUMP_CONTROL liveDumpControl = {0};
    ULONG returnLength;

	liveDumpControl.Version = SYSDBG_LIVEDUMP_CONTROL_VERSION;
	liveDumpControl.DumpFileHandle = hFile;
	liveDumpControl.Flags = flags;
	liveDumpControl.AddPagesControl = pages;

	std::cout << "Starting live dump (please be patient and do not interrupt)..." << std::endl;

	status = NtSystemDebugControl(CONTROL_LIVE_KERNEL_DUMP, (PVOID)&liveDumpControl, sizeof(liveDumpControl), NULL, 0, &returnLength);

	if (!NT_SUCCESS(status))
	{
		std::cout << "Error: Live dump failed: " << std::hex <<status << std::endl;
		return false;
	}
	
	CloseHandle(hFile);

	// Disable debug privilege
	if (!changeDebugPrivilege(false))
	{
		std::cout << "Warning: Failed to disable debug privilege after live dump" << std::endl;
	}

	std::cout << "Live dump completed successfully, file saved to " << finalDumpPath << std::endl;
	return true;
}
