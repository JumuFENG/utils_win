#ifndef _HELPER_MY_WINHELPER_H
#define _HELPER_MY_WINHELPER_H

#include "tstring.h"
#include <io.h>
#include <Windows.h>
#include <Wtsapi32.h>
#pragma comment(lib, "Wtsapi32.lib")
#include <ShlObj.h>
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")
#include <locale.h>
#include "iconv.h"
#include <algorithm>

//本文件所有接口函数均采用string不使用wstring。即使内部采用wstring，也进行转换之后输出
namespace helper{
    namespace basic{
        inline int version_compare(const std::string& v1, const string& v2)
        {
            if (v1 == v2)
            {
                return 0;
            }

            bool bV1Less = false;
            using std::string;
            string::size_type v1Start = string::npos, v2Start = string::npos;
            string::size_type v1End = string::npos, v2End = string::npos;
            do 
            {
                v1Start = v1End + 1;
                v2Start = v2End + 1;

                v1End = v1.find_first_of('.', v1Start);
                if (v1End == string::npos)
                {
                    v1End = v1.length();
                }
                v2End = v2.find_first_of('.', v2Start);
                if (v2End == string::npos)
                {
                    v2End = v2.length();
                }

                int verA = 0, verB = 0;
                if (v1End > v1Start)
                {
                    verA = atoi(v1.substr(v1Start, v1End - v1Start).c_str());
                }
                if (v2End > v2Start)
                {
                    verB = atoi(v2.substr(v2Start, v2End - v2Start).c_str());
                }

                if (verA != verB)
                {
                    bV1Less = (verA < verB);
                    break;
                }

                if (v1End == v1.length() && v2End == v2.length())
                {
                    return 0;
                }
            } while (v1End < v1.length() || v2End < v2.length());

            return bV1Less ? -1 : 1;
        }
    }

	namespace base64{
		static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

		static inline bool is_base64(unsigned char c) 
		{
			return (isalnum(c) || (c == '+') || (c == '/'));
		}

		static std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len)
		{
			std::string ret;
			int i = 0;
			int j = 0;
			unsigned char char_array_3[3];
			unsigned char char_array_4[4];

			while (in_len--) {
				char_array_3[i++] = *(bytes_to_encode++);
				if (i == 3) {
					char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
					char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
					char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
					char_array_4[3] = char_array_3[2] & 0x3f;

					for(i = 0; (i <4) ; i++)
						ret += base64_chars[char_array_4[i]];
					i = 0;
				}
			}

			if (i)
			{
				for(j = i; j < 3; j++)
					char_array_3[j] = '\0';

				char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
				char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
				char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
				char_array_4[3] = char_array_3[2] & 0x3f;

				for (j = 0; (j < i + 1); j++)
					ret += base64_chars[char_array_4[j]];

				while((i++ < 3))
					ret += '=';

			}

			return ret;

		}

		static std::string base64_decode(std::string const& encoded_string) 
		{
			int in_len = encoded_string.size();
			int i = 0;
			int j = 0;
			int in_ = 0;
			unsigned char char_array_4[4], char_array_3[3];
			std::string ret;

			while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
				char_array_4[i++] = encoded_string[in_]; in_++;
				if (i ==4) {
					for (i = 0; i <4; i++)
						char_array_4[i] = base64_chars.find(char_array_4[i]);

					char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
					char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
					char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

					for (i = 0; (i < 3); i++)
						ret += char_array_3[i];
					i = 0;
				}
			}

			if (i) {
				for (j = i; j <4; j++)
					char_array_4[j] = 0;

				for (j = 0; j <4; j++)
					char_array_4[j] = base64_chars.find(char_array_4[j]);

				char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
				char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
				char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

				for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
			}

			return ret;
		}

		static std::string base64_encode(std::string const& str_to_encode)
		{
			return base64_encode((unsigned char const*)(str_to_encode.c_str()),str_to_encode.length());
		}
	}

	namespace charset{//#include <boost/locale/encoding.hpp>
		//boost库中有相关功能，可研究，下面的代码可以实现转换，但使用了windows API
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

		inline std::wstring iconv_string_to_wstring(const std::string& szFrom )
		{
#ifdef USE_STRING_ICONV
			size_t from_len = szFrom.length();
			wchar_t*  wszTo = new wchar_t[from_len+1]; 
			const char* pszFrom = (const char*)(szFrom.c_str());  
			char* pszTo = (char*)wszTo;      // 虽然我们的目标类型是wchar_t数组，这里依然当做char来处理  
			//size_t from_len = strlen(szFrom); // 这里是字节数，如果是wchar_t的话，要乘上 sizeof(wchar_t)  
			size_t to_len = from_len * sizeof(wchar_t); // 
			char* pszTail = (char*)wszTo + to_len;
			iconv_t cd = iconv_open("wchar_t", "GB2312");   // 由gb2312转化为wchar_t  
			iconv(cd, &pszFrom, &from_len, &pszTo, &to_len);
			iconv_close(cd);
			*((wchar_t*)(pszTail - to_len)) = L'\0';
			std::wstring rWstr = std::wstring(wszTo);
			delete[] wszTo;
			wszTo = NULL;
			return rWstr;
#else
            return string_to_wstring(szFrom);
#endif
		}

		inline std::string iconv_wstring_to_string(const std::wstring& wszFrom )
		{
#ifdef USE_STRING_ICONV
			size_t from_len = wszFrom.length() * sizeof(wchar_t);  //传入字符串的字节数
			char*  szTo = new char[from_len+1]; 
			const char* pwszFrom = (const char*)(wszFrom.c_str());  
			char* pszTo = (char*)szTo;      // 
			size_t to_len = from_len; // 
			char* pszTail = (char*)szTo + to_len;
			iconv_t cd = iconv_open("GB2312", "wchar_t");   // 由wchar_t转化为gb2312 
			iconv(cd, &pwszFrom, &from_len, &pszTo, &to_len);
			iconv_close(cd);
			*(pszTail - to_len) = '\0';
			std::string rStr = std::string(szTo);
			delete[] szTo;
			szTo = NULL;
			return rStr;
#else
            return wstring_to_string(wszFrom);
#endif
		}
	}

	namespace os_util{
		//系统相关，主要用于windows系统，获取操作系统相关信息、常用文件夹等
		typedef BOOL (WINAPI *LPFN_ISWOW64PROCESS) (HANDLE, PBOOL);
		inline bool is_64os(HANDLE hProc=NULL)
		{
			BOOL bIsWow64 = FALSE;
			LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandle(TEXT("kernel32")), "IsWow64Process");
			if(NULL != fnIsWow64Process)
			{
				if (!fnIsWow64Process(hProc==NULL ? GetCurrentProcess() : hProc, &bIsWow64))
				{
					bIsWow64 = FALSE;
				}
			}
			return bIsWow64 ? true : false;
		}

		inline bool is_64proc(HANDLE hProc=NULL)
		{
			SYSTEM_INFO sysinfo;
			GetNativeSystemInfo(&sysinfo);
			if (sysinfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64 || sysinfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
				return !is_64os(hProc);
			return false;
		}

		inline bool is_vista_win7()
		{
			OSVERSIONINFO ver = {sizeof(OSVERSIONINFO), 0};
			GetVersionEx(&ver);
			return (ver.dwMajorVersion >= 6);
		}

		// 提升进程权限
		inline BOOL StartElevatedProcess(LPCTSTR szPrivName)
		{
			HANDLE hToken;
			TOKEN_PRIVILEGES tp;
			LUID luid;
			//打开进程令牌环
			if (!OpenProcessToken(GetCurrentProcess(),
				TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,
				&hToken))
			{
				printf("OpenProcessToken error.\n");
				return true;
			}
			//获得进程本地唯一ID
			if (!LookupPrivilegeValue(NULL,szPrivName,&luid))
			{
				printf("LookupPrivilege error!\n");
			}

			tp.PrivilegeCount = 1;
			tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
			tp.Privileges[0].Luid = luid;
			//调整权限
			if (!AdjustTokenPrivileges(hToken,0,&tp,sizeof(TOKEN_PRIVILEGES),NULL,NULL))
			{
				printf("AdjustTokenPrivileges error!\n");
				return true;
			}
			return false;
		}

		// 提升用户权限,来自sockmon，可能是以管理员权限运行的代码
		inline DWORD ElevatedProcess(LPCTSTR szExecutable, LPCTSTR szCmdLine)
		{
			SHELLEXECUTEINFO sei = {sizeof(SHELLEXECUTEINFO)};

			sei.lpVerb = TEXT("runas");
			sei.lpFile = szExecutable;
			sei.lpParameters = szCmdLine;
			sei.nShow = SW_SHOWNORMAL;
			ShellExecuteEx(&sei);
			return(GetLastError());
		}

		//与前一个函数对比
// 		inline bool shell_execute_runas(const std::wstring& _file_name, DWORD& _exit_code)
// 		{
// 			SHELLEXECUTEINFO _info = {0};
// 			_info.cbSize = sizeof(SHELLEXECUTEINFO);
// 			_info.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_FLAG_NO_UI;
// 			_info.lpVerb = is_vista_win7() ? TEXT("runas") : TEXT("open");
// 			_info.lpFile = _file_name.c_str();
// 			_info.nShow = SW_HIDE;
// 			if (!::ShellExecuteEx(&_info))
// 			{
// 				return false;
// 			}
// 			if (::WaitForSingleObject(_info.hProcess, INFINITE) != 0)
// 			{
// 				::CloseHandle(_info.hProcess);
// 				return false;
// 			}
// 			if (!::GetExitCodeProcess(_info.hProcess, &_exit_code))
// 			{
// 				::CloseHandle(_info.hProcess);
// 				return false;
// 			}
// 			::CloseHandle(_info.hProcess);
// 			return true;
// 		}

		//与前面对比，测试效果，该函数应该是提升进程权限。
		inline bool EnablePrivilege(LPCTSTR lpszPrivilegeName, bool bEnable)
		{
			HANDLE hToken;
			TOKEN_PRIVILEGES tp = {0};
			LUID luid;
			if(!OpenProcessToken(GetCurrentProcess(), 
				TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY | TOKEN_READ,
				&hToken))
				return false;

			if(!LookupPrivilegeValue(NULL, lpszPrivilegeName, &luid))
				return true;

			tp.PrivilegeCount = 1;
			tp.Privileges[0].Luid = luid;
			tp.Privileges[0].Attributes = (bEnable) ? SE_PRIVILEGE_ENABLED : 0;
			AdjustTokenPrivileges(hToken,FALSE,&tp,NULL,NULL,NULL);
			CloseHandle(hToken);
			return (GetLastError() == ERROR_SUCCESS);
		}

		inline HANDLE GetCurrentSessionUserToken()
		{
			const DWORD active_session_id = ::WTSGetActiveConsoleSessionId();	
			if (active_session_id == -1)
			{
				return NULL;
			}
			HANDLE user_token = NULL;
			if (!::WTSQueryUserToken(active_session_id, &user_token))
			{
				if (!EnablePrivilege(SE_TCB_NAME, true) || !::WTSQueryUserToken(active_session_id, &user_token))
				{
					return NULL;
				}
			}
			return user_token;
		}

		inline std::string GetCurrentSessionUserName()
		{
			wchar_t* current_user_name = NULL;
			DWORD bytes_returned = 0;
			if (!::WTSQuerySessionInformationW(WTS_CURRENT_SERVER_HANDLE, WTS_CURRENT_SESSION, WTSUserName, &current_user_name, &bytes_returned))
			{
				return "";
			}
			const std::wstring result = current_user_name;
			WTSFreeMemory(current_user_name);
			return charset::wstring_to_string(result);
		}

		//获取系统中一些常用目录，具体取值参考ShlObj.h
		inline std::string get_locallow_dir_path(DWORD pathtype = CSIDL_APPDATA)
		{
			TCHAR szPath[MAX_PATH];//CSIDL_LOCAL_APPDATA,CSIDL_APPDATA
			SHGetFolderPath(NULL, pathtype, NULL, SHGFP_TYPE_CURRENT, szPath);
			std::string strPath;
#if defined(UNICODE) || defined(_UNICODE)
			std::wstring strPathW = szPath;
			strPath = charset::wstring_to_string(strPathW);
#else
			strPath = szPath;
#endif
			return strPath;
		}
	}

	namespace filepath{
		inline HMODULE GetCurrentModule()
		{ 
			HMODULE hModule = NULL;
			GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)GetCurrentModule, &hModule);
			return hModule;
		}

		//获取当前模块文件全路径，如dll可能与调用它的exe不在同一个目录下
		inline std::string get_current_module_fullpath()
		{
			const HMODULE module_handle = GetCurrentModule();
			if (module_handle == INVALID_HANDLE_VALUE)
				return "";
			std::string result;
			TCHAR path_buffer[MAX_PATH] = { 0 };
			if (GetModuleFileName(module_handle, path_buffer, MAX_PATH) != 0)
			{
#if defined(UNICODE)||defined(_UNICODE)
				result = charset::wstring_to_string(path_buffer);
#else
				result = path_buffer;
#endif
			}
			return result;
		}

		inline std::string get_current_module_folder()
		{
			std::string fpath = get_current_module_fullpath();
			return fpath.erase(fpath.rfind("\\"));
		}

		inline std::string get_current_module_name()
		{
			std::string fpath = get_current_module_fullpath();
			return fpath.substr(fpath.rfind("\\")+1);
		}

		inline void get_current_module_folder_name(std::string & folder, std::string & name)
		{
			std::string fpath = get_current_module_fullpath();
			size_t rpos = fpath.rfind("\\");
			name = fpath.substr(rpos+1);
			folder = fpath.erase(rpos);
		}

		//获取当前进程名
		inline std::string get_current_process_name()
		{
			TCHAR buffer[MAX_PATH] = {0};
			const DWORD num_error = ::GetModuleBaseName(GetCurrentProcess(), NULL, buffer, MAX_PATH);
			if (num_error == 0)
				return "";
#if defined(UNICODE)||defined(_UNICODE)
			return charset::wstring_to_string(buffer);
#else
			return buffer;
#endif
		}

		inline bool is_path_exist(const std::string& sPath)
		{
			// Remove the last slash if necessary.
			std::string path = sPath;

			if (path.length() <= 1)
			{
				return false;
			}
			if ( 0 == path.substr(path.length() - 1, 1).compare("\\") )
			{
				path = path.substr(0, path.length() - 1);
			}

			_finddata_t p = {0};
			const int num_error = (int)_findfirst(path.c_str(), &p);
			if (num_error != -1)
			{
				_findclose(num_error);
				return true;
			}
			return false;
		}
		
		inline bool create_folder(const std::string& _folder)
		{
			int _pre_idx = (int)_folder.find("\\");
			while (_pre_idx > 0)
			{
				const int _idx = (int)_folder.find("\\", _pre_idx + 1);
				const std::string _part_dir = _folder.substr(0, _idx);
				if (_part_dir.length() > 0 && !is_path_exist(_part_dir))
				{
#if defined(UNICODE) || defined(_UNICODE) 
					if (!::CreateDirectory(charset::string_to_wstring(_part_dir).c_str(),NULL))
						return false;
#else
					if (!::CreateDirectory(_part_dir.c_str(), NULL))
						return false;
#endif
				}
				if (-1 == _idx)
					break;
				_pre_idx = _idx + 1;
			}
			return true;
		}

		inline BOOL delete_file(const std::string& _path)
		{
#if defined(UNICODE)||defined(_UNICODE)
			return ::DeleteFile(charset::string_to_wstring(_path).c_str());
#else
			return ::DeleteFile(_path.c_str());
#endif
		}

		inline bool delete_file_ex(const std::string& _path)
		{
			if (delete_file(_path))
				return true;
			if (::GetLastError() != ERROR_ACCESS_DENIED)
				return false;
#if defined(UNICODE)||defined(_UNICODE)
			const unsigned long _attr = ::GetFileAttributes(charset::string_to_wstring(_path).c_str());
			if ((_attr & FILE_ATTRIBUTE_READONLY) == 0)
				return false;
			if (!::SetFileAttributes(charset::string_to_wstring(_path).c_str(), _attr & ~FILE_ATTRIBUTE_READONLY))
				return false;
#else
			const unsigned long _attr = ::GetFileAttributes(_path.c_str());
			if ((_attr & FILE_ATTRIBUTE_READONLY) == 0)
				return false;
			if (!::SetFileAttributes(_path.c_str(), _attr & ~FILE_ATTRIBUTE_READONLY))
				return false;
#endif
			return (bool)delete_file(_path);
		}

		inline BOOL remove_blank_directoy(std::string blk_dir)
		{
#if defined(UNICODE)||defined(_UNICODE)
			return ::RemoveDirectory(charset::string_to_wstring(blk_dir).c_str());
#else
			return ::RemoveDirectory(blk_dir.c_str());
#endif
		}

		inline bool remove_blank_directoy_ex(std::string blk_dir)
		{
			if (remove_blank_directoy(blk_dir))
			{
				return true;
			}
			if (::GetLastError() != ERROR_ACCESS_DENIED)
				return false;
#if defined(UNICODE)||defined(_UNICODE)
			const unsigned long _attr = ::GetFileAttributes(charset::string_to_wstring(blk_dir).c_str());
			if ((_attr & FILE_ATTRIBUTE_READONLY) == 0)
				return false;
			if (!::SetFileAttributes(charset::string_to_wstring(blk_dir).c_str(), _attr & ~FILE_ATTRIBUTE_READONLY))
				return false;
#else
			const unsigned long _attr = ::GetFileAttributes(blk_dir.c_str());
			if ((_attr & FILE_ATTRIBUTE_READONLY) == 0)
				return false;
			if (!::SetFileAttributes(blk_dir.c_str(), _attr & ~FILE_ATTRIBUTE_READONLY))
				return false;
#endif
			return (bool)remove_blank_directoy(blk_dir);
		}

		inline bool delete_folder(const std::string& _dir)
		{
			_finddata_t p = {0};
			const int n = (int)_findfirst((_dir + "\\*").c_str(), &p);
			if (n != -1 )
			{
				do 
				{
					if (strcmp(p.name, ".") != 0 && strcmp(p.name, "..") != 0)
					{
						if (p.attrib & _A_SUBDIR)
						{
							delete_folder(_dir + "\\" + p.name);
						}
						else
						{
							delete_file(_dir + "\\" + p.name);
						} 
					}
				} while (_findnext(n, &p) == 0);
				_findclose(n);
				return (bool)remove_blank_directoy(_dir);
			}
		}

		inline bool delete_folder_ex(const std::string& _dir)
		{
			if (delete_folder(_dir))
			{
				return true;
			}
			_finddata_t p = {0};
			const int n = (int)_findfirst((_dir + "\\*").c_str(), &p);
			if (n != -1 )
			{
				do 
				{
					if (strcmp(p.name, ".") != 0 && strcmp(p.name, "..") != 0)
					{
						if (p.attrib & _A_SUBDIR)
						{
							delete_folder_ex(_dir + "\\" + p.name);
						}
						else
						{
							delete_file_ex(_dir + "\\" + p.name);
						} 
					}
				} while (_findnext(n, &p) == 0);
				_findclose(n);
				return remove_blank_directoy_ex(_dir);
			}
		}

		//如果目标文件已经存在，则覆盖之
		inline BOOL copy_file_ex(const std::string& from, const std::string& to)
		{
			if (to.rfind("\\")!=-1)
			{
				std::string dstdir = to.substr(0,to.rfind("\\"));
				if(!is_path_exist(dstdir))
					create_folder(dstdir);
			}
#if defined(UNICODE)||defined(_UNICODE)
			return ::CopyFile(charset::string_to_wstring(from).c_str(), 
				charset::string_to_wstring(to).c_str(), FALSE);
#else
			return ::CopyFile(from.c_str(), to.c_str(), FALSE);
#endif
		}

		inline BOOL delete_when_reboot(const std::string& file_)
		{
#if defined(UNICODE)||defined(_UNICODE)
			return ::MoveFileEx(charset::string_to_wstring(file_).c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
#else
			return ::MoveFileEx(file_.c_str(), NULL, MOVEFILE_DELAY_UNTIL_REBOOT);
#endif
		}

	}

	//进程、线程相关
	namespace process{
		inline HANDLE create_global_mutex(const std::string arg_name)
		{
#if defined(UNICODE)||defined(_UNICODE)
			const std::wstring _full_name =  L"Global\\" + charset::string_to_wstring(arg_name);
			return ::CreateMutex(NULL, TRUE, _full_name.c_str());
#else
			const std::string _full_name_a = "Global\\" + arg_name;
			return ::CreateMutex(NULL, TRUE, _full_name_a.c_str());
#endif
		}

		inline bool is_global_mutex_exist(const std::string& _name)
		{
			if (!create_global_mutex(_name) || GetLastError() == ERROR_ALREADY_EXISTS)
				return true;
			return false;
		}

		inline bool createprocess_inherithandles(const tstring& cmd, DWORD* p_thread_id = NULL, bool show = false)
		{
			TCHAR command_buffer[512] = {0};
			_tcscpy_s(command_buffer, 512, cmd.c_str());
			STARTUPINFO startup_info = {0};
			startup_info.cb = sizeof(STARTUPINFO);
			startup_info.dwFlags = STARTF_USESHOWWINDOW;
			if (show)
				startup_info.wShowWindow = SW_SHOW;
			else
				startup_info.wShowWindow = SW_HIDE;
			PROCESS_INFORMATION process_information = {0};
			if (!CreateProcess(NULL, command_buffer, NULL, NULL,
                TRUE, NORMAL_PRIORITY_CLASS, 0, 0, &startup_info, &process_information))
			{
				return false;
			}
			CloseHandle(process_information.hProcess);
			CloseHandle(process_information.hThread);
			if (p_thread_id)
				*p_thread_id = process_information.dwThreadId;
			return true;
		}

        inline DWORD get_process_by_name(const tstring& procname)
        {
            DWORD dwProcArray[2048], dwNeeded, cbMNeeded;
            HMODULE hModuleArray[2048];
            TCHAR szProcName[MAX_PATH] = {0};

            if (!EnumProcesses(dwProcArray, sizeof(dwProcArray), &dwNeeded))
            {
                return 0;
            }

            DWORD dwProcCount = dwNeeded / sizeof(DWORD);
            for (UINT i = 0; i < dwProcCount; i++)
            {
                HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | SYNCHRONIZE, FALSE, dwProcArray[i]);
                if (NULL == hProcess) continue;

                EnumProcessModules(hProcess, hModuleArray, sizeof(hModuleArray), &cbMNeeded);
                GetModuleFileNameEx(hProcess, hModuleArray[0], szProcName, sizeof(szProcName));

                tstring curProName = szProcName;
                if (curProName.length() <= 0) continue;

                transform(curProName.begin(), curProName.end(), curProName.begin(), tolower);

                tstring tmpName = procname;
                transform(tmpName.begin(), tmpName.end(), tmpName.begin(), tolower);

                if (tstring::npos != curProName.find(tmpName))
                {
                    return dwProcArray[i];
                }

                if (INVALID_HANDLE_VALUE != hProcess)
                {
                    CloseHandle(hProcess);
                }
            }

            return 0;
        }

        inline unsigned long get_process_base_address(DWORD pid)
        {
            HANDLE hProcess=::OpenProcess(PROCESS_ALL_ACCESS,false,pid);//pid-->目标进程id

            //调用目标进程的GetModuleHandle（NULL方法）
            HANDLE hThread = ::CreateRemoteThread( hProcess, NULL, 0,
                (LPTHREAD_START_ROUTINE) ::GetModuleHandle,NULL, 0, NULL );

            ::WaitForSingleObject( hThread, INFINITE );

            DWORD hLibModule;
            // 获取GetModuleHandle(NULL)的返回值
            ::GetExitCodeThread( hThread, &hLibModule );//hLibModule就是目标进程的起始地址.
            CloseHandle(hThread);
            CloseHandle(hProcess);

            return hLibModule;
        }
	}

	//注册表操作相关接口
	namespace reg_operator{
		
		inline bool writekey(HKEY key,LPCTSTR sub_key, LPCTSTR name, const BYTE *lpData, DWORD size)
		{//create-->set--->close.如果已经存在，create相当于open
			HKEY _target_key;
			if (ERROR_SUCCESS != RegCreateKeyEx(
				key, sub_key, 0,NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, 
				&_target_key, NULL))
			{
				return false;
			}
			if(ERROR_SUCCESS != RegSetValueEx(_target_key, name, 0, REG_SZ, lpData, size))
			{
				return false;
			}

			RegCloseKey(_target_key);
			return true;
		}

		inline bool writekey(HKEY key,std::string sub_key, std::string name, std::string val)
		{
			LPCTSTR lpstr_subkey,lpstr_name;
#if defined(UNICODE) || defined(_UNICODE)
			lpstr_subkey = (LPCTSTR)(charset::string_to_wstring(sub_key)).c_str();
			lpstr_name = (LPCTSTR)(charset::string_to_wstring(name)).c_str();
#else
			lpstr_subkey = (LPCTSTR)sub_key.c_str();
			lpstr_name = (LPCTSTR)name.c_str();
#endif
			DWORD size = (val.length()+1)*sizeof(TCHAR);
			writekey(key, lpstr_subkey, lpstr_name, (const BYTE*)val.c_str(),size);
		}

		inline bool writekey(HKEY key,std::string sub_key, std::string name, DWORD val)
		{
			LPCTSTR lpstr_subkey,lpstr_name;
#if defined(UNICODE) || defined(_UNICODE)
			lpstr_subkey = (LPCTSTR)(charset::string_to_wstring(sub_key)).c_str();
			lpstr_name = (LPCTSTR)(charset::string_to_wstring(name)).c_str();
#else
			lpstr_subkey = (LPCTSTR)sub_key.c_str();
			lpstr_name = (LPCTSTR)name.c_str();
#endif
			DWORD size = sizeof(DWORD);
			writekey(key, lpstr_subkey, lpstr_name, (const BYTE*)&val, size);
		}

		inline bool deletekey(HKEY key,std::string sub_key, std::string name)
		{

		}
        
        inline size_t get_folder_size(const std::string& folder )
        {

        }
	}
}

#endif // _HELPER_MY_WINHELPER_H
