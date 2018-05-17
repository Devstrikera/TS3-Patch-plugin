#pragma once

#include <string>

namespace unique_instance {
	extern bool running(const std::string&);
	extern bool self(const std::string&);
	
	extern bool lock(const std::string&);
	extern bool change_state(const std::string&, int state, bool require_own);
	extern int state(const std::string&);
	extern bool unlock(const std::string &, bool require_own);
}