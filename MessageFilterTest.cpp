// RakNet MessageFilterTest.cpp
// vcpkg install MinHook

#include "RakPeerInterface.h"
#include "RakPeer.h"

#include "MessageFilter.h"
#include "MessageIdentifiers.h"
#include "RakSleep.h"
#include "BitStream.h"
#include "GetTime.h"
#include <stdio.h>

#include <windows.h>
#include <vector>
#include <atomic>
#include "Sig.hpp"
#include "MinHook.h"
inline void OutputDebug(const WCHAR* strOutputString, ...) {
	WCHAR strBuffer[4096] = { 0 };
	va_list vlArgs;
	va_start(vlArgs, strOutputString);
	//in stdio.h
	_vsnwprintf_s(strBuffer, ARRAYSIZE(strBuffer) - 1, ARRAYSIZE(strBuffer) - 1, strOutputString, vlArgs);
	va_end(vlArgs);
	OutputDebugStringW(strBuffer);
}

bool DetourRunUpdateCycle(RakNet::RakPeer* RakPeer,
                          RakNet::BitStream* updateBitStream);

decltype(&DetourRunUpdateCycle) OriRunUpdateCycle;

std::atomic_bool kCallOnce = false;

void CallOuts(RakNet::RakPeer* RakPeer,const char* buf) {
  std::vector<unsigned char> data{0x4A, 0x02, 0, 0, 0, 8, 0x2A, 0xCA, 0x80,0};

  unsigned char length = strlen(buf);
  data.push_back(length);

for (int i = 0; i < length; i++) {
    data.push_back(buf[i]);
  }

  RakPeer->Send((const char*)data.data(), data.size(), HIGH_PRIORITY, RELIABLE_ORDERED, 0,
                  RakNet::UNASSIGNED_SYSTEM_ADDRESS, true);

}

bool DetourRunUpdateCycle(RakNet::RakPeer* RakPeer,
	RakNet::BitStream* updateBitStream) {

	if (!kCallOnce) {

    CallOuts(RakPeer,"\\(@^0^@)/");

    kCallOnce = true;
  }








  return OriRunUpdateCycle(RakPeer, updateBitStream);
}

int main() {
  
	PVOID ExeBase = (PVOID)GetModuleHandleW(NULL);
	OutputDebug(L"[log]Exe Base %p\n", ExeBase);
	//IDA sigmaker
	const void* found = Sig::find(ExeBase, 7500800, "48 89 5C 24 18 55 56 57 41 54 41 55 41 56 41 57 48 81 EC B0");

	  if (!found) {
    OutputDebug(L"[log]Cant find RunUpdateCycle\n");
    return true;
  } else {
    OutputDebug(L"[log]RunUpdateCycle %p\n", found);
  }

  MH_STATUS Status = MH_Initialize();
  if (Status != MH_OK) {
    OutputDebug(L"[log]Cant Init MinHook\n");
    return true;
  }

   MH_CreateHook((LPVOID)found, DetourRunUpdateCycle, (LPVOID*)&OriRunUpdateCycle);

   MH_EnableHook(MH_ALL_HOOKS);

   while (!kCallOnce) {
     Sleep(500);
   }

   MH_RemoveHook((LPVOID)found);


  // 注意DllMain返回0马上就卸载了
  // 这样可以反复注入 方便测试
  // 注入器一般会显示失败(如Extreme Injector)
  return false;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
  switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
      return main();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
      break;
  }
  return TRUE;
}
