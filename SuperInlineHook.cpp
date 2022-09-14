#include <Windows.h>
#include <stdio.h>
#include <map>
#include <vector>
#include "SuperInlineHook.h"

#ifdef _WIN64







BOOL SuperInlineHook::fn_add_hook(ULONG_PTR uHookAddress, ULONG_PTR uTargetAddress)
{
	//shellcode
	//00007FF694152440 |<x64dbg.EntryPoint> | 48:83EC 08 | sub rsp, 0x8 |
	//00007FF694152444 | C74424 78563412 | mov dword ptr ss : [rsp] , 0x12345678 |
	//00007FF69415244C | C74424 04 21436587 | mov dword ptr ss : [rsp + 0x4] , 0x87654321 |

	this->m_Hook.insert(pair<ULONG_PTR,ULONG_PTR>(uHookAddress,uTargetAddress));

	char* aOriBytes=(char*)malloc(33);

	BOOL bOk = ReadProcessMemory((HANDLE)-1, (LPVOID)uHookAddress, aOriBytes, 33, 0);

	if (!bOk) {
		printf("读取内存出错！\n");
		return false;
	}

	this->m_HookBytes.insert(pair<ULONG_PTR,char*>(uHookAddress, aOriBytes));



	char shellcode[] = { 0x48,0x83,0xec,0x08,0xc7,0x04,0x24,0x00,0x00,0x00,0x00,0xc7,0x44,0x24,0x04,0x00,0x00,0x00,0x00,0xff,0x25,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};

	*(ULONG*)&shellcode[7] = *(ULONG*)&(uHookAddress);//低四个字节

	*(ULONG*)&shellcode[15] = *(ULONG*)((PUCHAR)&uHookAddress+4);//高四个字节


	*(ULONG_PTR*)&shellcode[25] = uTargetAddress;//jmp 的地址



	bOk=WriteProcessMemory((HANDLE)-1, (LPVOID)uHookAddress, shellcode, sizeof(shellcode), 0);

	if (!bOk) {
		printf("写入内存出错！\n");
		return false;
	}

	printf("x64SuperInlineHook:挂钩成功!\n");


	return true;
}

BOOL SuperInlineHook::fn_remove_hook(ULONG_PTR uOriHookAddr)
{
	auto uTargetAddr=this->m_Hook[uOriHookAddr];

	if (!uTargetAddr) {
		printf("没有这个hook函数!\n");
		return false;
	}

	char* _oriBytes = this->m_HookBytes[uOriHookAddr];

	auto bOk=WriteProcessMemory((HANDLE)-1, (LPVOID)uOriHookAddr, (LPVOID)_oriBytes, 33, 0);

	if (!bOk) {
		printf("写回原字节数组失败!\n");
		return false;
	}

	this->m_Hook.erase(uOriHookAddr);
	this->m_HookBytes.erase(uOriHookAddr);

	free(_oriBytes);

	printf("删除Hook成功!\n");

	return true;
}



#else





BOOL SuperInlineHook::fn_add_hook(ULONG_PTR uHookAddress, ULONG_PTR uTargetAddress)
{
	
	this->m_Hook.insert(pair<ULONG_PTR, ULONG_PTR>(uHookAddress, uTargetAddress));

	char* aOriBytes = (char*)malloc(10);

	BOOL bOk = ReadProcessMemory((HANDLE)-1, (LPVOID)uHookAddress, aOriBytes, 10, 0);

	if (!bOk) {
		printf("读取内存出错！\n");
		return false;
	}

	this->m_HookBytes.insert(pair<ULONG_PTR, char*>(uHookAddress, aOriBytes));


	//push eip
	//jmp @target
	char shellcode[] = { 0x68,0x00,0x00,0x00,0x00,0xe9,0x00,0x00,0x00,0x00 }; 

	*(ULONG_PTR*)&shellcode[1] = uHookAddress; //rip

	*(ULONG_PTR*)&shellcode[6] = (uTargetAddress -10- uHookAddress);
	

	bOk = WriteProcessMemory((HANDLE)-1, (LPVOID)uHookAddress, shellcode, sizeof(shellcode), 0);

	if (!bOk) {
		printf("写入内存出错！\n");
		return false;
	}

	printf("x86SuperInlineHook:挂钩成功!\n");


	return true;
	



}


BOOL SuperInlineHook::fn_remove_hook(ULONG_PTR uOriHookAddr)
{
	auto uTargetAddr = this->m_Hook[uOriHookAddr];

	if (!uTargetAddr) {
		printf("没有这个hook函数!\n");
		return false;
	}

	char* _oriBytes = this->m_HookBytes[uOriHookAddr];

	auto bOk = WriteProcessMemory((HANDLE)-1, (LPVOID)uOriHookAddr, (LPVOID)_oriBytes, 10, 0);

	if (!bOk) {
		printf("写回原字节数组失败!\n");
		return false;
	}

	this->m_Hook.erase(uOriHookAddr);
	this->m_HookBytes.erase(uOriHookAddr);

	free(_oriBytes);


	printf("删除Hook成功!\n");

	

	return 0;
}
#endif
