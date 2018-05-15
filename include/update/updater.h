#pragma once

#include <string>
#include <chrono>
#include <functional>
#include <utility>

namespace update {
    struct Version {
        int major;
        int minor;
        int patch;
        std::string additional;

        std::chrono::system_clock::time_point timestamp;

        inline bool valid() const { return timestamp.time_since_epoch().count() > 0; }

        inline bool operator>(const Version& other) const {
            if(other.major < this->major) return true;
            else if(other.major > this->major) return false;

            if(other.minor < this->minor) return true;
            else if(other.minor > this->minor) return false;

            if(other.patch < this->patch) return true;
            else if(other.patch > this->patch) return false;
            return false;
        }

        inline bool operator==(const Version& other) const {
            return this->major == other.major && this->minor == other.minor && this->patch == other.patch;
        }

        inline bool operator<(const Version& other) const { return other.operator>(*this); }
        inline bool operator>=(const Version& other) const { return this->operator>(other) || this->operator==(other); }
        inline bool operator<=(const Version& other) const { return this->operator<(other) || this->operator==(other); }

        std::string string(bool build = true);

		Version(int major, int minor, int patch, std::string additional, const std::chrono::system_clock::time_point &timestamp) : patch(patch), additional(std::move(additional)), timestamp(timestamp) {
			this->major = major;
			this->minor = minor;
		}
	};

	struct RemoteVersion : public Version {
		RemoteVersion(int major, int minor, int patch, const std::string &additional, const std::chrono::system_clock::time_point &timestamp, std::string url) : Version(major, minor, patch, additional, timestamp), url(std::move(url)) {}

		std::string url;
	};

    extern Version local_version();
    extern void remote_version(const std::function<void(RemoteVersion)>&);
	extern std::string last_error();
}