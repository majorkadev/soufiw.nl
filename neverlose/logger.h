#ifndef NEVERLOSE_LOGGER_H
#define NEVERLOSE_LOGGER_H
#include <ctime>
#include <string>
#include <iostream>
#include <iomanip>

#define ENTER_LOGGER(logger) logger.section(TEXT(__FUNCTION__))


class clogger
{
	std::wostream& stream;
    std::wstring name;
public:
    clogger(std::wstring& name, std::wostream& stream) : name(std::move(name)), stream(stream)
    {
        stream << L"============= Section " << this->name << L" start =============\n";
    };

    ~clogger()
    {
        stream << L"============= Section " << this->name << L" end =============\n";
    };

    template<typename T>
    clogger& operator<<(const T& in)
    {
        stream << in;
        return *this;
    };

    clogger& operator<<(std::wostream& (*manip)(std::wostream&))
    {
        stream << manip;
        return *this;
    };
};

class clog_manager
{
    std::wostream& stream;
    struct null_buffer : std::wstreambuf {
        wint_t overflow(wint_t c) override {
            return c;
        }
    };
    static inline null_buffer nb;
    static inline std::wostream nullb = std::wostream(&nb);
public:
    clog_manager() : stream(nullb) {};
    explicit clog_manager(std::wostream& stream) : stream(stream)
    {
        std::time_t now = std::time(nullptr);
        tm newtime;
        localtime_s(&newtime, &now);
        std::ios::sync_with_stdio(false);
        stream << L"Logger inited at " << std::put_time(&newtime, L"%Y-%m-%d %H:%M:%S") << '\n';
    };

    ~clog_manager()
    {
        std::time_t now = std::time(nullptr);
        tm newtime;
        localtime_s(&newtime, &now);

        stream << L"Logger terminated at " << std::put_time(&newtime, L"%Y-%m-%d %H:%M:%S");
        stream.flush();
    };

    clogger section(std::wstring section_name)
    {
        return clogger(section_name, stream);
    };
};

#endif // NEVERLOSE_LOGGER_H