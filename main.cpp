#include <Windows.h>
#include <iostream>
#include "SuperInlineHook.h"
#include <stdio.h>
#include <stdlib.h>

SuperInlineHook _sih;

#ifdef _WIN64
DWORD  ThreadProc(LPVOID lParam) { //0x0000000140015E20


	printf("没被Hook呀!\n");


	return 0;
}

void __stdcall HookFunc() { //0000000140015DB0

	printf("hook成功\n");
	_sih.fn_remove_hook((ULONG_PTR)0x0000000140015E20);

}

int  main() {


	ThreadProc(nullptr);


	_sih.fn_add_hook((ULONG_PTR)0x0000000140015E20, (ULONG_PTR)0x0000000140015DB0);


	ThreadProc(nullptr);


	return 0;
}




#else 

DWORD  ThreadProc(LPVOID lParam) { //0x004161D0


	printf("没被Hook呀!\n");


	return 0;
}

void __stdcall HookFunc() { //00416150

	printf("hook成功\n");
	_sih.fn_remove_hook((ULONG_PTR)0x004161D0);

}

int  main() {


	ThreadProc(nullptr);


	_sih.fn_add_hook((ULONG_PTR)0x004161D0, (ULONG_PTR)0x00416150);


	ThreadProc(nullptr);


	return 0;
}
#endif // _WIN64






