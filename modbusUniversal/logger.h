#pragma once
#include <time.h>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>
#include <mutex>  
#include <comdef.h>
#include <locale>
#include <codecvt>

#pragma warning(disable : 4996)

static std::string lp = "F:\\justLOG.txt";
static bool console = true;
class Logger {
private:
	static Logger *obj;
	std::string TimeString()
	{
		time_t tt = time(0);
		struct tm *loc = localtime(&tt);
		return this->format("%02d:%02d:%02d %02d.%02d.%d", loc->tm_hour, loc->tm_min, loc->tm_sec,
			loc->tm_mday, loc->tm_mon, loc->tm_year + 1900);
	}
	std::mutex& getSyncObj()
	{
		static std::mutex m;
		return m;
	}
	void Put2File(std::string msg)
	{
		getSyncObj().lock();
		std::ofstream ofs;
		ofs.open(lp, std::ios_base::app);
		ofs.seekp(std::ios::end);
		ofs << msg;
		ofs.close();
		getSyncObj().unlock();
	}
public:
	static Logger *getInstance()
	{
		if (obj == nullptr)
		{
			obj = new Logger();
		}
		return obj;
	}
	void Log(std::string Str)
	{
		std::string msg = this->TimeString() + ": " + Str + "\r\n";
		if (console)
		{
			std::cout << msg;
		}
		Put2File(msg);
	}
	void Log(char* Str)
	{
		std::string msg = this->TimeString() + ": " + Str + "\r\n";
		if (console)
		{
			std::cout << msg;
		}
		Put2File(msg);
	}
	void Log(char *site, HRESULT error)
	{
		_com_error err(error);
		const wchar_t *com_msg = err.ErrorMessage();
		std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
		std::string msg = this->TimeString() + ": "
			+ this->format("%s: %s\n", site, converter.to_bytes(com_msg).c_str());
		if (console)
		{
			std::cout << msg;
		}
		Put2File(msg);
	}
	std::string format(const char *fmt, ...)
	{
		va_list args;
		va_start(args, fmt);
		std::vector<char> v(1024);
		while (true)
		{
			va_list args2;
			va_copy(args2, args);
			int res = vsnprintf(v.data(), v.size(), fmt, args2);
			if ((res >= 0) && (res < static_cast<int>(v.size())))
			{
				va_end(args);
				va_end(args2);
				return std::string(v.data());
			}
			size_t size;
			if (res < 0)
				size = v.size() * 2;
			else
				size = static_cast<size_t>(res) + 1;
			v.clear();
			v.resize(size);
			va_end(args2);
		}
	}
};