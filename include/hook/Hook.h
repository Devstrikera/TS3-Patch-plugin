#pragma once


#ifdef WIN32
	#include <winsock2.h>
	#include <Windows.h>
	#include <WinInet.h>
	#include <WS2tcpip.h>
#else
	#include "netdb.h"
#endif
#include <string>

//Also includes windows.h
#include "include/process/memory.h"
#include "include/wrapper/License.h"

namespace hook {
	class Hook {
		public:

			virtual std::string name() const = 0;
			/**
			 * @return true if hooking is available
			 */
			virtual bool available(std::string&) = 0;
			/**
			 * @return true if hook successfully initialized (not hooked! Just tested if possible)
			 */
			virtual bool initializeHook(std::string&) = 0;

			virtual bool hook(std::string&) = 0;
			virtual bool unhook(std::string&) = 0;

		protected:
			std::unique_ptr<mem::CodeFragment> make_jmp(uintptr_t address, uintptr_t jmp_target, size_t length, bool use_call = true);

			static thread_local std::unique_ptr<wrapper::StaticLicense> costume_license;
			static thread_local uintptr_t costume_license_ptr;
		public:
			static uintptr_t getPublicKeyPtr();
			static int getaddrinfo(const char *name, const char *service, const addrinfo *req, addrinfo **pai);
	};
}