#ifndef _HELPER_T_STRING_H
#define _HELPER_T_STRING_H
#include <tchar.h>
#include <Windows.h>
#include <string>

#if defined (_UNICODE) || defined(UNICODE)
typedef std::wstring tstring;
#else 
typedef std::string tstring;
#endif

typedef tstring string_t;
using std::string;
using std::wstring;

namespace util_win{
    inline string to_string(string_t srcStr);
    inline wstring to_wstring(string_t srcStr);
    inline tstring to_tstring(wstring strSrc);
    inline tstring to_tstring(string strSrc);
}

namespace win_string_conv{
    inline std::wstring string_to_wstring(std::string const& inStr)
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

    inline std::string wstring_to_string(std::wstring const& inWstr)//
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
}

namespace util_win{
    inline string to_string(string_t srcStr)
    {
#if defined (_UNICODE) || defined(UNICODE)
        return win_string_conv::wstring_to_string(srcStr);
#else 
        return srcStr;
#endif
    }

    inline wstring to_wstring(string_t srcStr)
    {
#if defined (_UNICODE) || defined(UNICODE)
        return srcStr;
#else 
        return win_string_conv::string_to_wstring(srcStr);
#endif
    }

    inline string_t to_tstring(string strSrc)
    {
#if defined (_UNICODE) || defined(UNICODE)
        return win_string_conv::string_to_wstring(strSrc);
#else 
        return strSrc;
#endif
    }

    inline string_t to_tstring(wstring strSrc)
    {
#if defined (_UNICODE) || defined(UNICODE)
        return strSrc;
#else 
        return win_string_conv::wstring_to_string(strSrc);
#endif
    }
}

#endif // _HELPER_T_STRING_H
