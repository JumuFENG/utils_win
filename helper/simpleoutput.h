#ifndef SIMPLE_OUTPUT_LOGGER_H_
#define SIMPLE_OUTPUT_LOGGER_H_
#include <iostream>
#include <string>
#include <Windows.h>
#include <sstream>

#if defined DEBUG || defined _DEBUG
#define LOG(x) simpleoutputinfo(__FILE__, __FUNCTION__, __LINE__, x)
#define LOGX_A(format, ...) {char buf[1024]; sprintf(buf, format, ##__VA_ARGS__); LOG(buf); }
#define LOGX_W(format, ...) {wchar_t buf[1024]; swprintf(buf, format, ##__VA_ARGS__); LOG(buf); }
#ifdef _UNICODE
#define LOGX( ... ) LOGX_W(##__VA_ARGS__)
#else
#define LOGX( ... ) LOGX_A(##__VA_ARGS__)
#endif
#else
#define LOG(x)
#define LOGX(...)
#endif

namespace simplelog_converter {
	std::string inline wstring_to_string(std::wstring const& inWstr)//
	{
		int wslen = wcslen(inWstr.c_str());
		int len = WideCharToMultiByte(CP_ACP, 0, inWstr.c_str(), wslen, NULL, 0, NULL, NULL);
		char* m_char = new char[len + 1];
		WideCharToMultiByte(CP_ACP, 0, inWstr.c_str(), wslen, m_char, len, NULL, NULL);
		m_char[len] = '\0';
		std::string rStr = std::string(m_char);
		delete[] m_char;
		return rStr;
	}

	std::wstring inline string_to_wstring(std::string inStr)
	{
		int slen = strlen(inStr.c_str());
		int len = MultiByteToWideChar(CP_ACP, 0, inStr.c_str(), slen, NULL, 0);
		wchar_t* m_wchar = new wchar_t[len + 1];
		MultiByteToWideChar(CP_ACP, 0, inStr.c_str(), slen, m_wchar, len);
		m_wchar[len] = '\0';
		std::wstring rWstr = std::wstring(m_wchar);
		delete[] m_wchar;
		return rWstr;
	}
}

void inline simpleoutputinfo(char* f, char* u, int l, std::string str)
{
	std::stringstream ss;
	ss << f << " <" << u << "> [" << l << "] " << str << std::endl;
	OutputDebugStringA(ss.str().c_str());
	std::cout << ss.str();
}

void inline simpleoutputinfo(char* f, char* u, int l, std::wstring wstr)
{
	simpleoutputinfo(f, u, l, simplelog_converter::wstring_to_string(wstr));
}

#endif //SIMPLE_OUTPUT_LOGGER_H_
