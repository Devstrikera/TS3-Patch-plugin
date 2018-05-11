#pragma once

#include "include/wrapper/License.h"
#include <string>
#include <netdb.h>
#include <arpa/inet.h>
#include <include/process/memory.h>

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
	};

	class Linux64Hook : public Hook {
		public:
			std::string name() const override;
			bool available(std::string &string) override;
			bool initializeHook(std::string &string) override;
			bool hook(std::string&) override;
			bool unhook(std::string&) override;

		private:
			static uint64_t getPublicKeyPtr();
			static int injected(void* builder);
			static int getaddrinfo(const char *name, const char *service, const struct addrinfo *req, struct addrinfo **pai);

			std::unique_ptr<mem::CodeFragment> hook_getaddrinfo;
			std::unique_ptr<mem::CodeFragment> hook_getStaticLicense;
			std::unique_ptr<mem::CodeFragment> hook_cmd_clientinitivexpand2;

			static thread_local std::unique_ptr<wrapper::StaticLicense> costume_license;
			static thread_local uintptr_t costume_license_ptr;
	};
}