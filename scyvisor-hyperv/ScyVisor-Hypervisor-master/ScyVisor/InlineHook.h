#pragma once
#include "Utils.h"

typedef struct _INLINE_HOOK
{
	unsigned char Code[14];
	unsigned char JmpCode[14];

	void* Address;
	void* HookAddress;
	BOOLEAN IsInstalled;
} INLINE_HOOK, *PINLINE_HOOK_T;

BOOLEAN MakeInlineHook(PINLINE_HOOK_T Hook, VOID* HookFrom, VOID* HookTo, BOOLEAN Install);
BOOLEAN EnableInlineHook(PINLINE_HOOK_T Hook);
VOID DisableInlineHook(PINLINE_HOOK_T Hook);