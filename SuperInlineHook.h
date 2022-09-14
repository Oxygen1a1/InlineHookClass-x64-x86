#pragma once

#include <map>
#define MAX_SIZE 100

using namespace std;

#ifdef  _WIN64
//64位时的SuperInlineHook
class SuperInlineHook {

	map<ULONG_PTR, ULONG_PTR> m_Hook;
	map<ULONG_PTR, char*> m_HookBytes;
public:
	
	BOOL fn_add_hook(ULONG_PTR uHookAddress,ULONG_PTR uTargetAddress);
	BOOL fn_remove_hook(ULONG_PTR uOriHookAddr);

};
#else 
//32位时的SuperInlineHook
class SuperInlineHook {
	map<ULONG_PTR, ULONG_PTR> m_Hook;
	map<ULONG_PTR, char*> m_HookBytes;;//x32下一次hook 要用到5个字节(无视距离)
public:
	
	BOOL fn_add_hook(ULONG_PTR uHookAddress, ULONG_PTR uTargetAddress);
	BOOL fn_remove_hook(ULONG_PTR uOriHookAddr);
};

#endif
