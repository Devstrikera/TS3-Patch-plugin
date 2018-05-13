#pragma once

#include <cstdint>

#ifdef WIN32
	#include <Windows.h>
#else
    #include <zconf.h>
#endif

namespace wrapper {
	/**
	 * Got from TeamSpeak 3 Client [linux x64 3.1.9]
	 */
	struct StaticLicense {
		uint32_t unknown0 = 0; //Const 0
		u_char publicLicense[0x20]{};
		uint32_t unknown1 = 0; //Will be set to zero too
		u_char padding[0x20]{}; //could be the private license
		uint64_t flags = 1; //Const 1 (Seems to be some flags)
	};

	extern StaticLicense* static_license_root;
}