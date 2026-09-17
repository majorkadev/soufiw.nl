#include <intrin.h>

#include "internal_fixes.h"
#include "neverlosesdk.hpp"
#include "HookFn.h"
#include <winhttp.h>
#pragma comment(lib, "winhttp.lib")

//#define GHETTO_FIX

#ifdef GHETTO_FIX

static HINTERNET hSession = NULL;
static HINTERNET hConnection = NULL;

void __fastcall GetSerial(void* ecx, void* edx, std::string& out, nlohmann::json& request)
{
    /*
    Request: {"params":{"hash":"N9xnoBk9JkbYQ66WTtgAAAAAAAD/AP8AeaCdFAAAAAA=","hash2":"hKV0twE0V3XnSatdohvL8nJXRuIWjzJCUnQidy4ttcjiAa4N6nUi2Q=="},"type":4}
    Mine hash : sft4Nhk9JkYCUHF3UYgAACHJkIv/AP8Aa8mGuAAAAAA=, hash2: hKV0t81t04fnSatdTmWcTKLf9ZQ=
    */
    new (&out) std::string("g6w/cgN2AuDsLw3xrzboM1kbkLy+osvg0Y/j0LJnQf04GHbV8s5V4yReEk1mh3ZA2G72fHG3oOh7zlGEfR1nKw717WiwRwsrgSDfJtaTQz14VDDkayLBNV1DaT/qSyx8Frg1nXU0crRu1P/G+EPvH6nWNPYLZdUMIeqVCToEFhJnqiuRoAyypjFNiKnLEMiy5j2YvBcLCOC8yC3FPt/GGsvUldBqkmQGkBjIsXsSkut05txVxq7VDx1i9adKE4zalTzNHr0Vtd6DTr8aeH8NYHWPGWAsnTBkZlkNuRuhBTtgRTcIKxzGATTN4k8/JaXCpxri7IqsylvZgXQw+5zldLjAHqcAWw3OD5iQn8DtOoon+DrHm3k3FY6wIrCM1FzTdjAIcTvXSiWOURHiwA4sJ8ExR4dyBZMydo8aBAYjrRxcD9oDa/VVJT4cZfDkyWvRjI3WMyEajF2JhiGcjpjztmD8fyt9C16VXwLfoYuJnrX1/Dv8SZfCU6U2UhwJlxO5mkg+/IctveCdxy8IIiXTKwA5vmiEpXRuUu17SCdmJhFLZ+Jr6cTmrob4exSEggGRk6BTaVomOq4I6IpkVUBIUVup+4JvWFseL5UkPOQqHIO5Rxnj1jY+PjAWFPeeXSZsP8/ceEnX8J13tfb7PAqRSrpQ1Wv/y+OjaqMoPg9PiRE=");
    printf("Spoofed serial %s\n", request.dump().c_str());
};

void __fastcall MakeRequest(void* ecx, void* edx, std::string& out, std::string_view route, int _, int __)
{
    printf("[0x%p] 0x%p MakeRequest(%s, 0x%X, 0x%X) spoofed\n", NtCurrentThreadId(), _ReturnAddress(), route.data(), _, __);

    new (&out) std::string("");

    int size_needed = MultiByteToWideChar(CP_UTF8, 0, route.data(), route.size(), NULL, 0);
    wchar_t* wroute = (wchar_t*)malloc((size_needed + 1) * sizeof(wchar_t));

    if (wroute)
    {
        MultiByteToWideChar(CP_UTF8, 0, route.data(), (int)route.size(), wroute, size_needed);
        wroute[size_needed] = L'\0';
        HINTERNET hRequest = WinHttpOpenRequest(hConnection, L"GET", wroute, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
        free(wroute);
        if (hRequest && WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
        {
            if (WinHttpReceiveResponse(hRequest, NULL))
            {
                DWORD dwSize = 0;
                DWORD dwDownloaded = 0;

                do
                {
                    dwSize = 0;
                    if (!WinHttpQueryDataAvailable(hRequest, &dwSize) || dwSize == 0) break;

                    size_t oldSize = out.size();
                    out.resize(oldSize + dwSize);

                    if (!WinHttpReadData(hRequest, &out[oldSize], dwSize, &dwDownloaded))
                    {
                        out.resize(oldSize);
                        break;
                    };

                    if (dwDownloaded < dwSize)
                        out.resize(oldSize + dwDownloaded);

                } while (dwSize > 0);
            };
        };
        WinHttpCloseHandle(hRequest);
    };
};

void __fastcall Libreq(void* ecx, void* edx, std::string& out, std::string_view libname)
{
    new (&out) std::string(libname);
};

void hijack_requestor()
{
    hSession = WinHttpOpen(L"NLR/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession)
        hConnection = WinHttpConnect(hSession, L"127.0.0.1", 30031, 0);
    HookFn((PVOID)0x41BC78E0, GetSerial, 0);
    HookFn((PVOID)0x41BC98E0, MakeRequest, 0);
    HookFn((PVOID)0x41BC9670, Libreq, 0);
};

#else // !GHETTO_FIX

void* reqtram = 0;
void* hkReqInst()
{
    printf("[0x%p] 0x%p Requestor::Instance\n", NtCurrentThreadId(), _ReturnAddress());
    //return *(PPVOID)0x42518C58;
    return reinterpret_cast<decltype(&hkReqInst)>(reqtram)();
};


class NLR_Requestor : public neverlosesdk::network::Requestor
{
	HINTERNET hSession;
	HINTERNET hConnection;

    void MakeRequest(std::string& out, std::string_view route, int _, int __) override
    {
        printf("[0x%p] 0x%p MakeRequest(%s, 0x%X, 0x%X) spoofed\n", NtCurrentThreadId(), _ReturnAddress(), route.data(), _, __);

        new (&out) std::string("");

        int size_needed = MultiByteToWideChar(CP_UTF8, 0, route.data(), route.size(), NULL, 0);
        wchar_t* wroute = (wchar_t*)malloc((size_needed + 1) * sizeof(wchar_t));

        if (wroute)
        {
            MultiByteToWideChar(CP_UTF8, 0, route.data(), (int)route.size(), wroute, size_needed);
            wroute[size_needed] = L'\0';
            HINTERNET hRequest = WinHttpOpenRequest(hConnection, L"GET", wroute, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
            free(wroute);
            if (hRequest && WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0))
            {
                if (WinHttpReceiveResponse(hRequest, NULL))
                {
                    DWORD dwSize = 0;
                    DWORD dwDownloaded = 0;

                    do
                    {
                        dwSize = 0;
                        if (!WinHttpQueryDataAvailable(hRequest, &dwSize) || dwSize == 0) break;

                        size_t oldSize = out.size();
                        out.resize(oldSize + dwSize);

                        if (!WinHttpReadData(hRequest, &out[oldSize], dwSize, &dwDownloaded))
                        {
                            out.resize(oldSize);
                            break;
                        };

                        if (dwDownloaded < dwSize)
                            out.resize(oldSize + dwDownloaded);

                    } while (dwSize > 0);
                };
            };
            WinHttpCloseHandle(hRequest);
        };
    };
    /*
    Request: {"params":{"hash":"N9xnoBk9JkbYQ66WTtgAAAAAAAD/AP8AeaCdFAAAAAA=","hash2":"hKV0twE0V3XnSatdohvL8nJXRuIWjzJCUnQidy4ttcjiAa4N6nUi2Q=="},"type":4}
    Mine hash : sft4Nhk9JkYCUHF3UYgAACHJkIv/AP8Aa8mGuAAAAAA=, hash2: hKV0t81t04fnSatdTmWcTKLf9ZQ=
    */
    void GetSerial(std::string& out, nlohmann::json& request) override
    {
        printf("[GetSerial] called from 0x%p\n", _ReturnAddress()); fflush(stdout);
        // __try
        // {
            printf("[GetSerial] request: %s\n", request.dump().c_str()); fflush(stdout);
            if (request.contains("params"))
            {
                auto& p = request["params"];
                if (p.contains("hash"))
                    printf("[GetSerial] hash:  %s\n", p["hash"].get<std::string>().c_str());
                if (p.contains("hash2"))
                    printf("[GetSerial] hash2: %s\n", p["hash2"].get<std::string>().c_str());
                fflush(stdout);
            }
        // }
        // __except (EXCEPTION_EXECUTE_HANDLER)
        // {
        //     printf("[GetSerial] WARNING: crashed reading request (debug/release STL mismatch?)\n"); fflush(stdout);
        // }
        new (&out) std::string("g6w/cgN2AuDsLw3xrzboM1kbkLy+osvg0Y/j0LJnQf04GHbV8s5V4yReEk1mh3ZA2G72fHG3oOh7zlGEfR1nKw717WiwRwsrgSDfJtaTQz14VDDkayLBNV1DaT/qSyx8Frg1nXU0crRu1P/G+EPvH6nWNPYLZdUMIeqVCToEFhJnqiuRoAyypjFNiKnLEMiy5j2YvBcLCOC8yC3FPt/GGsvUldBqkmQGkBjIsXsSkut05txVxq7VDx1i9adKE4zalTzNHr0Vtd6DTr8aeH8NYHWPGWAsnTBkZlkNuRuhBTtgRTcIKxzGATTN4k8/JaXCpxri7IqsylvZgXQw+5zldLjAHqcAWw3OD5iQn8DtOoon+DrHm3k3FY6wIrCM1FzTdjAIcTvXSiWOURHiwA4sJ8ExR4dyBZMydo8aBAYjrRxcD9oDa/VVJT4cZfDkyWvRjI3WMyEajF2JhiGcjpjztmD8fyt9C16VXwLfoYuJnrX1/Dv8SZfCU6U2UhwJlxO5mkg+/IctveCdxy8IIiXTKwA5vmiEpXRuUu17SCdmJhFLZ+Jr6cTmrob4exSEggGRk6BTaVomOq4I6IpkVUBIUVup+4JvWFseL5UkPOQqHIO5Rxnj1jY+PjAWFPeeXSZsP8/ceEnX8J13tfb7PAqRSrpQ1Wv/y+OjaqMoPg9PiRE=");
        printf("[GetSerial] returned serial (%zu bytes)\n", out.size()); fflush(stdout);
    };
    void fn2() override { printf("[0x%p] 0x%p %s\n", NtCurrentThreadId(), _ReturnAddress(), __FUNCTION__); NtSuspendProcess(NtCurrentProcess()); };
    void fn3() override { printf("[0x%p] 0x%p %s\n", NtCurrentThreadId(), _ReturnAddress(), __FUNCTION__); NtSuspendProcess(NtCurrentProcess()); };
    void QueryLuaLibrary(std::string& out, std::string_view name) override { new (&out) std::string(name); };

public:
    NLR_Requestor() : hSession(NULL), hConnection(NULL)
    {
        hSession = WinHttpOpen(L"NLR/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (hSession)
            hConnection = WinHttpConnect(hSession, L"127.0.0.1", 30031, 0);
    };
};

void hijack_requestor()
{
    *(neverlosesdk::network::Requestor**)0x42518C58 = new NLR_Requestor;
    *(PDWORD)0x42518C54 = 0x80000004;
    HookFn((PVOID)0x41BC9450, hkReqInst, 0, &reqtram);
};

#endif // GHETTO_FIX