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
#include <tlhelp32.h>

#include <cstdio>
#include <format>
#include <memory>
#include <mutex>
#include <set>
#include <regex>
#include <string>

#include <boost/dll/runtime_symbol_info.hpp>
#include <boost/program_options.hpp>

#include <bwprint.h>

namespace po = boost::program_options;

using wregex = std::basic_regex<WCHAR>;

namespace {
// NOLINTBEGIN(cppcoreguidelines-avoid-non-const-global-variables)
std::set<DWORD> g_injected_processes;
std::mutex g_injected_processes_mutex;
// NOLINTEND(cppcoreguidelines-avoid-non-const-global-variables)
}  // namespace

const DWORD PROCESS_LIST_POLL_INTERVAL = 500;

const wregex GIMP_PROCESS_REGEX(LR"(gimp(-[0-9.]+)?\.exe)", std::regex_constants::ECMAScript);

struct handle_deleter
{
  void operator()(HANDLE h) const noexcept
  {
    ::CloseHandle(h);
  }
  using pointer = HANDLE;
};

using unique_handle = const std::unique_ptr<HANDLE, handle_deleter>;

struct virtualfree_deleter
{
  virtualfree_deleter(HANDLE process) : process(process) {}

  void operator()(LPVOID p) const noexcept
  {
    ::VirtualFreeEx(process, p, 0, MEM_RELEASE);
  }
  using pointer = LPVOID;

 private:
  HANDLE process;
};

using unique_virtual = const std::unique_ptr<LPVOID, virtualfree_deleter>;

VOID CALLBACK ProcessExitCallback(PVOID lpParameter, BOOLEAN /* TimerOrWaitFired */)
{
  auto process_id = ::PtrToUlong(lpParameter);

  bw::print(L"PID {0} exited, removing from list\n", process_id);
  {
    const std::lock_guard<std::mutex> lk(g_injected_processes_mutex);
    g_injected_processes.erase(process_id);
  }

  return;
}

bool InjectDLL(DWORD process_id, const WCHAR* dll_path)
{
  unique_handle process(::OpenProcess(
      PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | SYNCHRONIZE, FALSE, process_id));
  if (!process)
    return false;

  auto dll_path_size = (wcslen(dll_path) + 1) * sizeof(WCHAR);

  unique_virtual remote_string(::VirtualAllocEx(process.get(), nullptr, dll_path_size, MEM_COMMIT, PAGE_READWRITE), virtualfree_deleter(process.get()));
  if (!remote_string)
    return false;

  if (!::WriteProcessMemory(process.get(), remote_string.get(), dll_path, dll_path_size, nullptr))
    return false;

  auto kernel = ::GetModuleHandle(L"kernel32.dll");
  if (!kernel)
    return false;

  {
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto ll = reinterpret_cast<LPTHREAD_START_ROUTINE>(::GetProcAddress(kernel, "LoadLibraryW"));
    unique_handle remote_thread(::CreateRemoteThread(process.get(), nullptr, 0, ll, remote_string.get(), 0, nullptr));
    if (!remote_thread)
      return false;

    ::WaitForSingleObject(remote_thread.get(), INFINITE);
  }

  {
    const std::lock_guard<std::mutex> lk(g_injected_processes_mutex);
    g_injected_processes.insert(process_id);
  }

  HANDLE wait_handle = INVALID_HANDLE_VALUE;
  ::RegisterWaitForSingleObject(&wait_handle, process.get(), ProcessExitCallback, ::UlongToPtr(process_id), INFINITE, WT_EXECUTEONLYONCE);
  // UnregisterWait
  // https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-unregisterwait

  return true;
}

void MonitorProcesses(const wregex& process_regex, const WCHAR* dll_path)
{
  while (true) {
    unique_handle snapshot(::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
    if (snapshot.get() != INVALID_HANDLE_VALUE) {
      PROCESSENTRY32 pe;
      pe.dwSize = sizeof(PROCESSENTRY32);

      if (::Process32First(snapshot.get(), &pe)) {
        while (true) {
          if (std::regex_match(static_cast<PTCHAR>(pe.szExeFile), process_regex)) {
            auto process_id = pe.th32ProcessID;
            if (!g_injected_processes.contains(process_id)) {
              bw::print(L"Injecting into {0} (PID {1})\n", pe.szExeFile, process_id);
              InjectDLL(process_id, dll_path);
            }
          }
          if (!::Process32Next(snapshot.get(), &pe))
            break;
        }
      }
    }

    ::Sleep(PROCESS_LIST_POLL_INTERVAL);
  }
}

int wmain(int argc, wchar_t const** argv) noexcept
{
  try {
    po::options_description desc("Allowed options");
    desc.add_options()("help", "produce help message")("dll", po::wvalue<std::wstring>(), "set dll to inject");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help")) {
      std::cout << desc << "\n";
      return 0;
    }

    std::wstring dll_path;

    if (vm.count("dll")) {
      dll_path = vm["dll"].as<std::wstring>();
    } else {
      boost::system::error_code ec;
      auto program_directory = boost::dll::program_location(ec).remove_filename();
      if (ec) {
        std::cerr << "Failed to get program location" << std::endl;
        return 1;
      }

      dll_path = (program_directory / L"dll.dll").wstring();
    }

    bw::print(L"Trying to inject {}\n", dll_path);

    MonitorProcesses(GIMP_PROCESS_REGEX, dll_path.c_str());
  } catch (const std::exception& ex) {
    std::cerr << "Unhandled exception: " << ex.what() << std::endl;
    return 1;
  } catch (...) {
    std::cerr << "Unknown exception occurred." << std::endl;
    return 1;
  }

  return 0;
}
