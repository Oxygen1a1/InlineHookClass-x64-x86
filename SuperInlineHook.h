#pragma once

#include <map>
#define MAX_SIZE 100

using namespace std;

#ifdef  _WIN64
//64λʱ��SuperInlineHook
class SuperInlineHook {

	map<ULONG_PTR, ULONG_PTR> m_Hook;
	map<ULONG_PTR, char*> m_HookBytes;
public:
	
	BOOL fn_add_hook(ULONG_PTR uHookAddress,ULONG_PTR uTargetAddress);
	BOOL fn_remove_hook(ULONG_PTR uOriHookAddr);

};
#else 
//32λʱ��SuperInlineHook
class SuperInlineHook {
	map<ULONG_PTR, ULONG_PTR> m_Hook;
	map<ULONG_PTR, char*> m_HookBytes;;//x32��һ��hook Ҫ�õ�5���ֽ�(���Ӿ���)
public:
	
	BOOL fn_add_hook(ULONG_PTR uHookAddress, ULONG_PTR uTargetAddress);
	BOOL fn_remove_hook(ULONG_PTR uOriHookAddr);
};

#endif
