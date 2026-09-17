#ifndef SERVER_LAUNCHER_H
#define SERVER_LAUNCHER_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>
#include <filesystem>
#include <thread>
#include <chrono>

#pragma comment(lib, "ws2_32.lib")

namespace ServerLauncher
{
    inline bool IsPortOpen(const char* ip, u_short port)
    {
        WSADATA wsaData;
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
            return false;

        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET)
        {
            WSACleanup();
            return false;
        }

        DWORD timeoutMs = 300;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeoutMs, sizeof(timeoutMs));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip, &addr.sin_addr);

        bool connected = false;
        if (connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0)
        {
            connected = true;
        }

        closesocket(sock);
        WSACleanup();
        return connected;
    }

    inline bool EnsureServerRunning(u_short port = 30031)
    {
        if (IsPortOpen("127.0.0.1", port))
        {
            printf("[+] Local server is already running on port %u.\n", port);
            fflush(stdout);
            return true;
        }

        printf("[*] Local server not detected on port %u. Starting Rust server automatically...\n", port);
        fflush(stdout);

        std::vector<std::pair<std::string, std::string>> candidates = {
            { "C:\\Users\\YOURNAMEHERE\\Desktop\\rust-server 27042026\\target\\release\\neverlose-server.exe", "C:\\Users\\YOURNAMEHERE\\Desktop\\rust-server 27042026" },
            { "server\\rust-server\\target\\release\\neverlose-server.exe", "server\\rust-server" },
            { "..\\server\\rust-server\\target\\release\\neverlose-server.exe", "..\\server\\rust-server" },
            { "C:\\Users\\YOURNAMEHERE\\Desktop\\rust-server 27042026", "C:\\Users\\YOURNAMEHERE\\Desktop\\rust-server 27042026" },
            { "server\\rust-server", "server\\rust-server" }
        };

        std::string selectedExecPath;
        std::string selectedWorkDir;
        bool isDirectExe = false;

        for (const auto& [execPath, workDir] : candidates)
        {
            if (std::filesystem::exists(execPath))
            {
                if (std::filesystem::is_regular_file(execPath) && execPath.find(".exe") != std::string::npos)
                {
                    selectedExecPath = execPath;
                    selectedWorkDir = workDir;
                    isDirectExe = true;
                    break;
                }
                else if (std::filesystem::is_directory(execPath))
                {
                    selectedExecPath = execPath;
                    selectedWorkDir = workDir;
                    isDirectExe = false;
                    break;
                }
            }
        }

        STARTUPINFOA si{};
        PROCESS_INFORMATION pi{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOWMINNOACTIVE;

        std::string cmdLine;
        std::string workDirStr;

        if (isDirectExe)
        {
            cmdLine = "\"" + selectedExecPath + "\"";
            workDirStr = selectedWorkDir;
            printf("[*] Executing binary: %s (WorkDir: %s)\n", cmdLine.c_str(), workDirStr.c_str());
        }
        else
        {
            std::string dir = selectedWorkDir.empty() ? "C:\\Users\\YOURNAMEHERE\\Desktop\\rust-server 27042026" : selectedWorkDir;
            cmdLine = "cmd.exe /c cargo run --release";
            workDirStr = dir;
            printf("[*] Executing command: %s (WorkDir: %s)\n", cmdLine.c_str(), workDirStr.c_str());
        }

        fflush(stdout);

        char cmdBuf[1024];
        strncpy(cmdBuf, cmdLine.c_str(), sizeof(cmdBuf) - 1);
        cmdBuf[sizeof(cmdBuf) - 1] = '\0';

        BOOL created = CreateProcessA(
            NULL,
            cmdBuf,
            NULL,
            NULL,
            FALSE,
            CREATE_NEW_CONSOLE,
            NULL,
            workDirStr.empty() ? NULL : workDirStr.c_str(),
            &si,
            &pi
        );

        if (!created)
        {
            printf("[-] Failed to launch Rust server process. Error code: %lu\n", GetLastError());
            fflush(stdout);
            return false;
        }

        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        printf("[*] Waiting for Rust server to respond on port %u...\n", port);
        fflush(stdout);

        for (int i = 0; i < 80; ++i)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(250));
            if (IsPortOpen("127.0.0.1", port))
            {
                printf("[+] Rust server successfully initialized and responding on port %u!\n", port);
                fflush(stdout);
                return true;
            }
        }

        printf("[-] Timed out waiting for Rust server on port %u.\n", port);
        fflush(stdout);
        return false;
    }
}

#endif // SERVER_LAUNCHER_H
