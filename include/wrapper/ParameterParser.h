#pragma once

#include <string>
#include "general.h"

#ifdef WIN32
	typedef unsigned __int64 ssize_t;
#endif

namespace wrapper {
	class ParameterParser {
		public:
			typedef int(*fn_getParamValueID)(void*, const TSString&, ssize_t& index);

#ifdef WIN32
			typedef void*(*fn_getParamValue)(void*, void*, const TSString&, ssize_t& index);
#else
			typedef void*(*fn_getParamValue)(std::string&, void*, const TSString&, ssize& index);
#endif
			typedef int(*fn_getLastError)(void*);
			typedef int(*fn_getParamIndex)(void*, const TSString&, ssize_t& index);
		public:
			ParameterParser() = delete;
			~ParameterParser() = default;

			int getParamValueID(const TSString& key, ssize_t& index);
			std::string getParamValue(const TSString& key, ssize_t& index);
			//Causes sometimes a crash!
#ifdef IMPLEMENT_DEPRECATED
			__attribute_deprecated__ int getParamIndex(const TSString& key, int& index);
#endif
			int getLastError();

			bool hasParam(const TSString& key);
		private:
	};

	namespace impl {
		struct ParameterParserFunctions {
#ifndef WIN32
			ParameterParser::fn_getLastError getLastError;
#endif
			ParameterParser::fn_getParamIndex getParamIndex;
			ParameterParser::fn_getParamValue getParamValue;
			ParameterParser::fn_getParamValueID getParamValueID;
		};
		extern ParameterParserFunctions* fn_ParameterParser;
	}
}