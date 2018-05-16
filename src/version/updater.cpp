#include "include/update/updater.h"
#include "include/ini_reader.h"
#include <mutex>
#include <vector>
#include <iostream>
#include <curl/curl.h>
#include <thread>

using namespace std;
using namespace std::chrono;
using namespace update;

std::string Version::string(bool build) {
    return to_string(this->major) + '.' + to_string(this->minor) + '.' + to_string(this->patch) + this->additional + (build ? " [Build: " + to_string(duration_cast<seconds>(this->timestamp.time_since_epoch()).count()) + "]" : "");
}

#ifdef WIN32
#include <ctime>
#include <iomanip>
#include <sstream>

extern "C" char* strptime(const char* s, const char* f, struct tm* tm) {
	std::istringstream input(s);
	input.imbue(std::locale(setlocale(LC_ALL, nullptr)));
	input >> std::get_time(tm, f);
	if (input.fail()) {
		return nullptr;
	}
	return (char*)(s + input.tellg());
}
#endif

unique_ptr<Version> local_version{[]() -> Version* {
    const char* build_timestamp = __TIME__; //23:59:01
    const char* build_date = __DATE__;      //Feb 12 1996

	cout << "Time " << build_timestamp << " date " << build_date << endl;
    tm timestamp{}, date{};
    if(!strptime(build_timestamp, "%H:%M:%S", &timestamp)) cerr << "Could not parse build timestamp!" << endl;
    if(!strptime(build_date, "%b %d %Y", &date)) cerr << "Could not parse build date!" << endl;

    system_clock::time_point time = system_clock::time_point() + seconds(mktime(&date)) + hours(timestamp.tm_hour) + minutes(timestamp.tm_min) + seconds(timestamp.tm_sec);
    return new Version{0, 1, 2, "", time};
}()};
Version update::local_version() {
    return *::local_version;
}

mutex remote_lock;
bool fetching = false;
vector<std::function<void(RemoteVersion)>> remote_callbacks;
unique_ptr<RemoteVersion> remote_version;
string remote_fetch_error;

std::string update::last_error() { return remote_fetch_error; }

struct VersionRequestLock {
    ~VersionRequestLock() {
        unique_lock<mutex> lock(remote_lock);
        if(!::remote_version) ::remote_version.reset(new RemoteVersion{0, 0, 0, "", system_clock::time_point(), ""});

        fetching = false;
        for(const auto& fn : remote_callbacks)
            fn(*::remote_version);
        remote_callbacks.clear();
    }
};

bool request_version_info(string& error);
void update::remote_version(const std::function<void(RemoteVersion)>& callback){
    unique_lock<mutex> lock(remote_lock);
    if(::remote_version) {
        lock.release();
        callback(*::remote_version);
    } else {
        remote_callbacks.push_back(callback);
        if(!fetching) {
            fetching = true;
            thread([=]{
                VersionRequestLock local_lock{};

                string response;
                if(!request_version_info(response)) {
					remote_fetch_error = "Fained to request version! (" + response +")";
                    cerr << remote_fetch_error << endl;
                    return;
                }

                auto reader = INIReader(response, true);
                if(reader.ParseError()) {
					remote_fetch_error = "Could not read ini file! (Line " + to_string(reader.ParseError()) +")";
					cerr << remote_fetch_error << endl;
                    cerr << "Ini file:" << endl;
					cerr << response << endl;
					return;
                }

                {
                    unique_lock<mutex> l(remote_lock);
#ifdef WIN32
	#ifdef ENV32
					auto section = "windows_32";
	#else
					auto section = "windows_64";
	#endif
#else
					auto section = "linux_64";
#endif
                    ::remote_version.reset(new RemoteVersion{
							(int) reader.GetInteger(section, "major", -1),
							(int) reader.GetInteger(section, "minor", -1),
							(int) reader.GetInteger(section, "patch", -1),
							reader.Get(section, "additional", ""),
							system_clock::time_point() + seconds(reader.GetInteger(section, "timestamp", 0)),
							reader.Get(section, "url", "")
					});
                }
            }).detach();
        }
    }
}
#define ERROR(message)          \
do {                            \
    cerr << message << endl;    \
    return size;                \
} while(false)

size_t local_write_callback(char *buffer, size_t size, size_t nmemb, std::string* target) {
    target->append(buffer, size * nmemb);
    return size * nmemb;
}
#undef ERROR

#define ERROR(message)  \
do {                    \
    error = message;    \
    return false;       \
} while(false)

bool curl_init = false;
bool request_version_info(string& error) {
    if(!curl_init) {
        //curl_global_init(CURL_GLOBAL_ALL);
        curl_init = true;
    }

    string response;
    CURLcode code = CURLE_OK;
    unique_ptr<CURL, void(*)(void*)> handle(curl_easy_init(), ::curl_easy_cleanup);

    if(!handle) ERROR("Could not spawn curl handle");
    if(code = curl_easy_setopt(handle.get(), CURLOPT_URL, "http://plugin.teaspeak.de/ts3_patch.info")) ERROR("Could not set url (" + string(curl_easy_strerror(code)) + ")");
    if(code = curl_easy_setopt(handle.get(), CURLOPT_WRITEFUNCTION, &local_write_callback)) ERROR("Could not set write callback (" + string(curl_easy_strerror(code)) + ")");
    if(code = curl_easy_setopt(handle.get(), CURLOPT_WRITEDATA, &response)) ERROR("Could not set write buffer (" + string(curl_easy_strerror(code)) + ")");
    if(code = curl_easy_setopt(handle.get(), CURLOPT_NOPROGRESS, 1l)) ERROR("Could not disable no progress (" + string(curl_easy_strerror(code)) + ")");
    if(code = curl_easy_setopt(handle.get(), CURLOPT_TIMEOUT_MS, 5000l)) ERROR("Could not set timeout (" + string(curl_easy_strerror(code)) + ")");
    if(code = curl_easy_setopt(handle.get(), CURLOPT_SSL_VERIFYPEER, 0L)) ERROR("Could not disable ssl verify peer (" + string(curl_easy_strerror(code)) + ")");
    if(code = curl_easy_perform(handle.get())) ERROR("Could not perform curl request! (" + string(curl_easy_strerror(code)) + ")");

    long response_code;
    if(code = curl_easy_getinfo(handle.get(), CURLINFO_RESPONSE_CODE, &response_code)) ERROR("Could not get response code (" + string(curl_easy_strerror(code)) + ")");
    if(response_code != 200L) ERROR("Invalid response code (" + to_string(response_code) + ") (" + string(curl_easy_strerror(code)) + ")");

    error = response;
    return true;
}