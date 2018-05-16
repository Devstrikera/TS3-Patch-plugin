#include "include/wrapper/ParameterParser.h"
#include "include/hook/Hook.h"
#include "include/gui/helper.h"
#include <QApplication>
#include <QMessageBox>
#include <iostream>
#include <cassert>
#include <include/config.h>
#include <include/base64.h>
#include <include/core.h>
#include <thread>

#ifdef WIN32
	#include <in6addr.h>
#else
    #include <arpa/inet.h>
	#include <netinet/in.h>
#endif

using namespace hook;
using namespace wrapper;
using namespace std;

std::unique_ptr<wrapper::StaticLicense> thread_local Hook::costume_license;
uintptr_t thread_local Hook::costume_license_ptr;

std::unique_ptr<mem::CodeFragment> Hook::make_jmp(uintptr_t address, uintptr_t jmp_target, size_t length, bool use_call) {
	assert(length >= 12);
	//Instructions are equal on windows & linux :D
	u_char buffer[12] = {
			0x48, 0xb8,                             //movabs %rax, $address
			(jmp_target >>  0) & 0xFF,
			(jmp_target >>  8) & 0xFF,
			(jmp_target >> 16) & 0xFF,
			(jmp_target >> 24) & 0xFF,
			(jmp_target >> 32) & 0xFF,
			(jmp_target >> 40) & 0xFF,
			(jmp_target >> 48) & 0xFF,
			(jmp_target >> 56) & 0xFF,

			//0xff, 0xe0,                           //jmp %rax
			//0xff, 0xd0,                           //call %rax
			0xff, use_call ? (u_char) 0xd0 : (u_char) 0xe0,
	};
	return mem::replace(address, buffer, 12, length);
}

int Hook::getaddrinfo(const char *name, const char *service, const addrinfo *req, addrinfo **pai) {
	if(!plugin::configuration->blacklist.enabled) {
		plugin::message("[color=red]Blacklist patch isn't enabled.[/color]", PLUGIN_MESSAGE_TARGET_SERVER);
		plugin::message("[color=red]Allowing blacklist check![/color]", PLUGIN_MESSAGE_TARGET_SERVER);
		return ::getaddrinfo(name, service, req, pai);
	}
	printf("Getting address info: %s\n", name);
	printf(" req: %p\n", req);
	printf(" pai: %p\n", pai);
	printf(" service: %p\n", (void*) service);
	printf(" name: %p\n",(void*)  name);
	auto result = ::getaddrinfo(name, service, req, pai);
	if(result > 0) return result;

	string addr(name);
	if(addr.find("blacklist") != string::npos) {
		cout << "Blacklist request! Original response: " << endl;
		for(auto entry = *pai; entry != nullptr; entry = entry->ai_next) {
			if(entry->ai_addr->sa_family == AF_INET6) {
				char astring[INET6_ADDRSTRLEN];
				auto addr = ((sockaddr_in6*) entry->ai_addr)->sin6_addr;
				inet_ntop(AF_INET6, &addr, astring, INET6_ADDRSTRLEN);
				cout << "Replacing " << astring << " to :::::" << endl;
#ifdef WIN32
				auto& buffer = ((sockaddr_in6*) entry->ai_addr)->sin6_addr.u;
				memset(buffer.Byte, 0, 16);
#else
                auto& buffer = ((sockaddr_in6*) entry->ai_addr)->sin6_addr.__in6_u;
                memset(buffer.__u6_addr8, 0, 16);
#endif
			} else if(entry->ai_addr->sa_family == AF_INET) {
				cout << "Replacing " << inet_ntoa(((sockaddr_in *) entry->ai_addr)->sin_addr) << " to 0.0.0.0" << endl;
				((sockaddr_in *) entry->ai_addr)->sin_addr.s_addr = 0;
			}
		}
	}
	cout << "Request proceeded: " << result << endl;
	return result;
}

uintptr_t Hook::getPublicKeyPtr() {
	auto result = (uintptr_t)

#ifdef WIN32
            wrapper::static_license_root;
#else
            &wrapper::static_license_root;
#endif
	cout << "Got license root key request!" << endl;
	if(costume_license && costume_license_ptr > 0) {
		cout << "Using costume license key! (" << costume_license_ptr << ")" << endl;
#ifdef WIN32
		result = costume_license_ptr;
#else
        result = (uintptr_t) &costume_license_ptr;
#endif
	} else {
		cout << "Using the standard TeamSpeak 3 key!" << endl;
	}

	return (uintptr_t)  result;
}

void Hook::injected(wrapper::ParameterParser* parser) {
	ssize_t index = 0;
	cout << "proof: " << parser->getParamValue("proof", index) << " -> " << index << " error: " << parser->getLastError() << endl;
	cout << "l: " << parser->getParamValue("l", index) << " -> " << index << " error: " << parser->getLastError() << endl;
	cout << "root: " << parser->getParamValue("root", index) << " -> " << index << " error: " << parser->getLastError() << endl;

	costume_license_ptr = 0;
	costume_license.reset();
	if(parser->hasParam("root")) {
		if(!plugin::configuration->license.enabled) {
			cout << "Costume license disabled but wants to connect to a costume server!" << endl;
			QApplication::instance();
			runOnThread(QApplication::instance()->thread(), []{
				QMessageBox::critical(nullptr, QString::fromStdString(plugin::name()), "Could not connect to target server!\nThe target server is using a costume license and requires this plugin!\nEnable the feature TeaSpeak license within the plugin config.");
				return;
			});
		} else {
			cout << "Contained a costume root key" << endl;
			auto costume_root = parser->getParamValue("root", index);
			cout << "Root key: " << costume_root << endl;
			auto root = base64::decode(costume_root);
			cout << "Length: " << root.length() << endl;

			costume_license.reset(new wrapper::StaticLicense{});
			memcpy(costume_license->publicLicense, root.data(), 32);
			costume_license_ptr = (uintptr_t) costume_license.get();
		}
	}
}