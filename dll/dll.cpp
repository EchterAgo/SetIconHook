// Set Icon Hook
// Copyright (c) 2023 Axel Gembe
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <detours/detours.h>

#include <fstream>
#include <string>

namespace {
auto RealSendMessage = SendMessageW;  // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
}  // namespace

LRESULT WINAPI DetouredSendMessage(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
{
  if (Msg == WM_SETICON)
    return 0;

  return RealSendMessage(hWnd, Msg, wParam, lParam);
}

BOOL APIENTRY DllMain(HMODULE /* hModule */, DWORD dwReason, LPVOID /* lpReserved */)
{
  if (DetourIsHelperProcess()) {
    return TRUE;
  }

  switch (dwReason) {
    case DLL_PROCESS_ATTACH:
      DetourRestoreAfterWith();

      DetourTransactionBegin();
      DetourUpdateThread(GetCurrentThread());
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast, clang-diagnostic-microsoft-cast)
      DetourAttach(reinterpret_cast<PVOID *>(&RealSendMessage), DetouredSendMessage);
      DetourTransactionCommit();
      break;
    case DLL_PROCESS_DETACH:
      DetourTransactionBegin();
      DetourUpdateThread(GetCurrentThread());
      // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast, clang-diagnostic-microsoft-cast)
      DetourDetach(reinterpret_cast<PVOID *>(&RealSendMessage), DetouredSendMessage);
      DetourTransactionCommit();
      break;
    default:
      break;
  }

  return TRUE;
}
