#ifndef SIMPLE_OUTPUT_LOGGER_H_
#define SIMPLE_OUTPUT_LOGGER_H_
#include <iostream>
#include <string>
#include <Windows.h>
#include <sstream>

#if defined DEBUG || defined _DEBUG
#define LOG(x) simpleoutputinfo(__FILE__, __LINE__, x)
#define LOG2(x,y) simpleoutputinfo(__FILE__, __LINE__, x, y)
#define LOGX(format, ...) {char buf[1024]; sprintf(buf, format, ##__VA_ARGS__); LOG(buf); }
#else
#define LOG(x)
#define LOG2(x,y)
#define LOGX(format, ...)
#endif

namespace simplelog_converter{
	std::string inline wstring_to_string(std::wstring const& inWstr)//
	{
		int wslen = wcslen(inWstr.c_str());
		int len= WideCharToMultiByte(CP_ACP,0,inWstr.c_str(),wslen,NULL,0,NULL,NULL);  
		char* m_char=new char[len+1];  
		WideCharToMultiByte(CP_ACP,0,inWstr.c_str(),wslen,m_char,len,NULL,NULL);  
		m_char[len]='\0'; 
		std::string rStr = std::string(m_char);
		delete[] m_char;
		return rStr;
	}

	std::wstring inline string_to_wstring(std::string inStr)
	{
		int slen = strlen(inStr.c_str());
		int len = MultiByteToWideChar(CP_ACP,0,inStr.c_str(),slen,NULL,0);
		wchar_t* m_wchar=new wchar_t[len+1];  
		MultiByteToWideChar(CP_ACP,0,inStr.c_str(),slen,m_wchar,len);  
		m_wchar[len]='\0';
		std::wstring rWstr = std::wstring(m_wchar);
		delete[] m_wchar;
		return rWstr;
	}
}

void inline simpleoutputinfo(char* f, int l, std::string str)
{
    std::stringstream ss;
    ss<<f<<"["<<l<<"] "<<str;
	OutputDebugStringA(ss.str().c_str());
	std::cout<<ss.str()<<std::endl;
}

template <typename T>
void simpleoutputinfo(char* f, int l, T t)
{
	std::stringstream ss;
	ss<<t;
	simpleoutputinfo(f, l, ss.str());
}

template <typename T>
void simpleoutputinfo(char* f, int l, const std::string& prefix,T t)
{
	std::string str = prefix + " ";
#ifdef _UNICODE
	std::wstringstream wss;
	wss<<t;
	std::wstring wstr = wss.str();
	str += simplelog_converter::wstring_to_string(wstr);;
#else
	std::stringstream ss;
	ss<<t;
	str += ss.str();
#endif
	simpleoutputinfo(f, l, str);
}

#endif //SIMPLE_OUTPUT_LOGGER_H_
