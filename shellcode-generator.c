#include <windows.h>

BOOL write_file(const wchar_t * file_path, const char * buf, int length) {
	HANDLE hFile = CreateFile(
		file_path,
		GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ,
		0,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		0);
	if (hFile == INVALID_HANDLE_VALUE) {
		return FALSE;
	}

	DWORD tmp;
	WriteFile(hFile, buf, length, &tmp, 0);
	CloseHandle(hFile);
	return TRUE;
}

extern void shellcode_CodeStart();
extern void shellcode_CodeEnd();

int main() {
	// Get code start and end address
	unsigned char *pStart = (unsigned char *)&shellcode_CodeStart;
	unsigned char *pEnd = (unsigned char *)&shellcode_CodeEnd;

	char *out = malloc((pEnd - pStart) * 8);
	strcpy(out, "const unsigned char shellcode[] = {\n");
	int count = 1;
	for (auto i = 0; i < pEnd - pStart; i++) {
		char szData[16] = { 0 };
		sprintf_s(szData, 16, "0x%02x, ", (unsigned char)(pStart[i]));
		strcat(out, szData);
		if (count == 16) {
			strcat(out, "\n");
			count = 0;
		}
		count++;
	}
	strcat(out, "};");

#ifdef _WIN64
#define SHELLCODE_H L"shellcode_x64.h"
#else
#define SHELLCODE_H L"shellcode.h"
#endif // _WIN64

	// save shellcode.h
	DeleteFile(SHELLCODE_H);
	write_file(SHELLCODE_H, (const char*)out, strlen(out));
	free(out);

	// debug
	// mmLoaderCodeStart();

	return 0;
}
