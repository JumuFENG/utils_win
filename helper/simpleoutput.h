#ifndef SIMPLE_OUTPUT_LOGGER_H_
#define SIMPLE_OUTPUT_LOGGER_H_
#include <iostream>
#include <string>
#include <Windows.h>
#include <sstream>

#define LOG(x) simpleoutputinfo(x)
#define LOG2(x,y) simpleoutputinfo(x,y)

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

void inline simpleoutputinfo(std::string str)
{
#if defined DEBUG || defined _DEBUG
	OutputDebugStringA(str.c_str());
	std::cout<<str<<std::endl;
#endif
}

template <typename T>
void simpleoutputinfo(T t)
{
#if defined DEBUG || defined _DEBUG
	std::stringstream ss;
	ss<<t;
	simpleoutputinfo(ss.str());
#endif
}

template <typename T>
void simpleoutputinfo(const std::string& prefix,T t)
{
#if defined DEBUG || defined _DEBUG
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
	simpleoutputinfo(str);
#endif
}

#endif //SIMPLE_OUTPUT_LOGGER_H_
