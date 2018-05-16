#pragma once

#include <string>
namespace file {
	extern std::string resolveSymbolicLink(const std::string&);
	extern bool exists(const std::string&);
	extern bool mkdirs(const std::string&);
}