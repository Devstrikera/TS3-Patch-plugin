#pragma once

#include "Hook.h"
#include <netdb.h>
#include <arpa/inet.h>

namespace hook {
	class Linux64Hook : public Hook {
		public:
		std::string name() const override;
		bool available(std::string &string) override;
		bool initializeHook(std::string &string) override;
		bool hook(std::string&) override;
		bool unhook(std::string&) override;

		private:

		std::unique_ptr<mem::CodeFragment> hook_getaddrinfo;
		std::unique_ptr<mem::CodeFragment> hook_getStaticLicense;
		std::unique_ptr<mem::CodeFragment> hook_cmd_clientinitivexpand2;
	};
}