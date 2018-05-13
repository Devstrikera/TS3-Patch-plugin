#pragma once

#include "hook.h"

#ifdef ENV32
	#define MODULE_NAME ("ts3client_win32.exe")
#else
	#define MODULE_NAME ("ts3client_win64.exe")
#endif

namespace hook {
	class HookWindows64 : public Hook {
		public:
		std::string name() const override;
		bool available(std::string &string) override;
		bool initializeHook(std::string &string) override;
		bool hook(std::string&) override;
		bool unhook(std::string&) override;

		private:
		//static uint64_t getPublicKeyPtr();
		//static int injected(void* builder);

		std::unique_ptr<mem::CodeFragment> hook_getaddrinfo;
		std::unique_ptr<mem::CodeFragment> hook_getStaticLicense;
		std::unique_ptr<mem::CodeFragment> hook_cmd_clientinitivexpand2;

		public:
			static void injected(void* builder);
	};
}