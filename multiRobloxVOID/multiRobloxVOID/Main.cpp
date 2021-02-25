//https://www.unknowncheats.me/forum/general-programming-and-reversing/202534-mutexkiller.html

#include "Main.h"
#define WIN32_LEAN_AND_MEAN

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName);
BOOL IsAdministrator(VOID);
BOOL ProcessExists(LPCWSTR process, int countAllIDs, DWORD usedProcIDs[]);

int main(int argc, char* argv[])
{
	const wchar_t* ProcessName = L"RobloxPlayerBeta.exe";
	HANDLE hProc[1024];
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	ULONG handleInfoSize = 0x10000;
	ULONG i;
	int j;
	DWORD procIDs[1024];
	DWORD usedProcIDs[1024];
	int countIDs = 0;
	int countAllIDs = 0; //added by wYn 8/17
	BOOL found = FALSE;
	BOOL used = FALSE;
	BOOL firstRun = TRUE;

	// casting to a PSTR type for the function, not sure if it will work but lets give it a shot
	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetLibraryProcAddress(const_cast<LPSTR>("ntdll.dll"), const_cast<LPSTR>("NtQuerySystemInformation"));
	_NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetLibraryProcAddress(const_cast<LPSTR>("ntdll.dll"), const_cast<LPSTR>("NtDuplicateObject"));
	_NtQueryObject NtQueryObject = (_NtQueryObject)GetLibraryProcAddress(const_cast<LPSTR>("ntdll.dll"), const_cast<LPSTR>("NtQueryObject"));
	SetConsoleTitleW(L"Roblox Multi-Game Launcher");
	printf("==========================\n");
	printf("    Coded by wYn#5984     \n");
	printf("==========================\n");
	printf(" DO NOT CLOSE THIS WINDOW \n");
	printf("==========================\n");
	if (IsAdministrator() == FALSE)
	{
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
		printf("\n[ERROR]: ");
		SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
		printf("Please run the program as administrator!\n");

		getchar();
		return EXIT_FAILURE;
	}
	/* Setting debug privileges. */
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid);
		tkp.PrivilegeCount = 1;
		tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(hToken, 0, &tkp, sizeof(tkp), NULL, NULL);
	}


	printf("\nWaiting for Roblox Client...\n");
	while (true)
	{
		while (!ProcessExists(ProcessName, countAllIDs, usedProcIDs)) {}
		Sleep(2000); // this was 2000 which is 2 seconds
		if (firstRun == TRUE) {
			printf("Roblox Client detected!\n");
			firstRun = FALSE;
		}
		countIDs = 0; // counter for current pids
		/* Searching the process name and save the found PIDs in an array. */
		hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		pe32.dwSize = sizeof(PROCESSENTRY32);
		if (!Process32First(hProcessSnap, &pe32))
			return EXIT_FAILURE;

		// check if the process has already been found and handle closed  -- added by wYn on 8/18
		for (int i = 0; i < countIDs; i++) {
			printf("PID in table:	%d\n", procIDs[j]);
			if (procIDs[i] == pe32.th32ProcessID) {
				printf("***Process already found****");
			}
		}

		do {
			if (wcscmp(pe32.szExeFile, ProcessName) == 0)   // this checks if the processname matches the current process name being looped
			{
				// added on 8/27 by wYn to check if procId has already been used
				used = FALSE; // reset used value
				for (int i = 0; i < countAllIDs; i++) {
					if (usedProcIDs[i] == pe32.th32ProcessID) {
						used = TRUE; // id already used so dont add it to the table
						//printf("***Process already used****");
						continue; // skip over this record since its already used
					}
				}
				//if (used == FALSE) {  //new pid that hasnt been used so add to list of pids to loop through and also add it to used list for checking in the next iteration
				//	procIDs[countIDs++] = pe32.th32ProcessID;
				//	usedProcIDs[countAllIDs++] = pe32.th32ProcessID;
				//}
				procIDs[countIDs++] = pe32.th32ProcessID;

			}
		} while (Process32Next(hProcessSnap, &pe32));
		CloseHandle(hProcessSnap);
		/* For the found PIDs of the process, we run our handle enumeration. */
		for (j = 0; j < countIDs; j++)
		{
			usedProcIDs[j] = procIDs[j]; // insert the current procID into the used procID list
			hProc[j] = OpenProcess(PROCESS_ALL_ACCESS, FALSE, procIDs[j]);
			if (!hProc[j])
			{
				SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
				printf("[ERROR]: ");
				SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
				printf("PID:	%d, OpenProcess failed!\n\n", procIDs[j]);

				getchar();
				return EXIT_FAILURE;
			}
			if (used == FALSE) {
				printf("===================\n");
				printf("PID:	%d\n", procIDs[j]);
				Sleep(3000); // 3000 which is 3 seconds waiting for handles to load
			}

			handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
			/* NtQuerySystemInformation won't give us the correct buffer size, so we guess by doubling the buffer size. */
			while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
			{
				handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
			}

			/* NtQuerySystemInformation stopped giving us STATUS_INFO_LENGTH_MISMATCH. */
			if (!NT_SUCCESS(status))
			{
				SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
				printf("\n[ERROR]: ");
				SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
				printf("NtQuerySystemInformation failed!\n\n");

				getchar();
				return EXIT_FAILURE;
			}

			for (i = 0; i < handleInfo->HandleCount; i++)
			{
				SYSTEM_HANDLE handle = handleInfo->Handles[i];
				HANDLE dupHandle = NULL;
				POBJECT_TYPE_INFORMATION objectTypeInfo;
				PVOID objectNameInfo;
				UNICODE_STRING objectName;
				ULONG returnLength;

				/* Check if this handle belongs to the PID the user specified. */
				if (handle.ProcessId != procIDs[j])
					continue;

				/* Duplicate the handle so we can query it. */
				if (!NT_SUCCESS(NtDuplicateObject(hProc[j], (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, 0, 0, 0)))
					continue;

				/* Query the object type. */
				objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
				if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL)))
				{
					CloseHandle(dupHandle);
					continue;
				}

				/* Query the object name (unless it has an access of 0x0012019f, on which NtQueryObject could hang. */
				if (handle.GrantedAccess == 0x0012019f)
				{
					free(objectTypeInfo);
					CloseHandle(dupHandle);
					continue;
				}

				objectNameInfo = malloc(0x1000);
				if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, 0x1000, &returnLength)))
				{
					/* Reallocate the buffer and try again. */
					objectNameInfo = realloc(objectNameInfo, returnLength);
					if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, returnLength, NULL)))
					{
						free(objectTypeInfo);
						free(objectNameInfo);
						CloseHandle(dupHandle);
						continue;
					}
				}

				/* Cast our buffer into an UNICODE_STRING. */
				objectName = *(PUNICODE_STRING)objectNameInfo;

				/* Work with the information we got. */
				if (objectName.Length)
				{

					/* Compare the handle name with the handle name we search. */
					if (wcscmp(objectName.Buffer, L"\\Sessions\\1\\BaseNamedObjects\\ROBLOX_singletonEvent") == 0 || (wcscmp(objectName.Buffer, L"\\Sessions\\2\\BaseNamedObjects\\ROBLOX_singletonEvent") == 0))
					{
						found = TRUE;
						printf("Roblox Singleton Event found:\n");
						printf("[%#x] %.*S: %.*S\n", handle.Handle, objectTypeInfo->Name.Length / 2, objectTypeInfo->Name.Buffer, objectName.Length / 2, objectName.Buffer);

						/* Trying to close the handle. */
						if (!DuplicateHandle(hProc[j], (HANDLE)handle.Handle, NULL, NULL, 0, FALSE, 0x1))
						{
							SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
							printf("\n[ERROR]: ");
							SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
							printf("DuplicateHandle failed!\n\n");
						}
						printf("Roblox Singleton Event Successfully killed!\n");
						usedProcIDs[countAllIDs++] = pe32.th32ProcessID; // add to already used procs
						//continue;
					}
				}

				free(objectTypeInfo);
				free(objectNameInfo);
				CloseHandle(dupHandle);
			}

			if (found == FALSE)
			{
				SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12);
				printf("\n[ERROR]: ");
				SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7);
				printf("Roblox Singleton Event not found or already killed!\n\n");
			}

			free(handleInfo);
			CloseHandle(hProc[j]);
		}

	}  //end of while true

	CloseHandle(hToken);
	getchar();



	return EXIT_SUCCESS;
}

void ClearVariables() {

}

/* Retrieves the address of an exported function or variable from the specified dynamic-link library (DLL). */
PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
	return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

/* Check if the program was executed with Admin rights. */
BOOL IsAdministrator(VOID)
{
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup;
	BOOL IsInAdminGroup = FALSE;

	if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdministratorsGroup))
	{
		return FALSE;
	}

	if (!CheckTokenMembership(NULL, AdministratorsGroup, &IsInAdminGroup))
	{
		IsInAdminGroup = FALSE;
	}

	FreeSid(AdministratorsGroup);
	return IsInAdminGroup;
}

/* Check if a program is running. */
BOOL ProcessExists(LPCWSTR process, int countAllIDs, DWORD usedProcIDs[])
{
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	pe32.dwSize = sizeof(PROCESSENTRY32);
	bool used = false;
	do {
		if (wcscmp(pe32.szExeFile, process) == 0)
		{
			CloseHandle(hProcessSnap);
			return TRUE;

		}
	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return FALSE;
}