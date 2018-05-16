#include <iostream>
#include "../../include/process/file.h"

#ifndef WIN32
	#include <zconf.h>

	using namespace std;
	std::string file::resolveSymbolicLink(const std::string& path) {
		char buffer[PATH_MAX];
		ssize_t len = ::readlink(path.c_str(), buffer, PATH_MAX);
		if(len < 0) len = 0;
		return string(buffer, len);

	}
#else
	#include <Windows.h>
	#include <iostream>
	#include <vector>
	#include <memory>
	#include <type_traits>

	std::string file::resolveSymbolicLink(const std::string& link) {
		return "";
	}
	std::wstring GetLinkTarget( const std::wstring& a_Link ) {
		// Define smart pointer type for automatic HANDLE cleanup.
		typedef std::unique_ptr<std::remove_pointer<HANDLE>::type, decltype( &::CloseHandle )> FileHandle;
		// Open file for querying only (no read/write access).
		FileHandle h( ::CreateFileW(a_Link.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr), &::CloseHandle );
		if (h.get() == INVALID_HANDLE_VALUE) {
			h.release();
			throw std::runtime_error( "CreateFileW() failed." );
		}

		const size_t requiredSize = ::GetFinalPathNameByHandleW( h.get(), nullptr, 0,
																 FILE_NAME_NORMALIZED );
		if ( requiredSize == 0 ) {
			throw std::runtime_error( "GetFinalPathNameByHandleW() failed." );
		}
		std::vector<wchar_t> buffer( requiredSize );
		::GetFinalPathNameByHandleW( h.get(), buffer.data(),
									 static_cast<DWORD>( buffer.size() ),
									 FILE_NAME_NORMALIZED );

		return std::wstring( buffer.begin(), buffer.end() - 1 );
	}


	bool file::exists(const std::string& path) {
		return GetFileAttributes(path.c_str()) != 0xFFFFFFFF;
	}

	bool file::mkdirs(const std::string& path) {
		return CreateDirectory(path.c_str(), nullptr) && file::exists(path);
	}
#endif