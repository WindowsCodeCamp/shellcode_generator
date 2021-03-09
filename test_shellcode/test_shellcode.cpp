// test_shellcode.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include <windows.h>
#ifdef _WIN64
#include "../shellcode_x64.h"
#else
#include "../shellcode.h"
#endif // _WIN64

int main()
{
	typedef VOID(*FUNC)(VOID);
	HANDLE HeapHandle = HeapCreate(HEAP_CREATE_ENABLE_EXECUTE, sizeof(shellcode), 0);
	FUNC pfnRun = (FUNC)HeapAlloc(HeapHandle, HEAP_ZERO_MEMORY, sizeof(shellcode));
	memcpy(pfnRun, shellcode, sizeof(shellcode));

	pfnRun();
}
