#pragma once

#include <string>
#include "general.h"

namespace wrapper {
	class ParameterParser {
		public:
			typedef int(*fn_getParamValueID)(void*, const TSString&, int& index);
			typedef void*(*fn_getParamValue)(std::string&, void*, const TSString&, int& index);
			typedef int(*fn_getLastError)(void*);
			typedef int(*fn_getParamIndex)(void*, const TSString&, int& index);
		public:
			ParameterParser() = delete;
			~ParameterParser() = default;

			int getParamValueID(const TSString& key, int& index);
			std::string getParamValue(const TSString& key, int& index);
			//Causes sometimes a crash!
			__attribute_deprecated__ int getParamIndex(const TSString& key, int& index);
			int getLastError();

			bool hasParam(const TSString& key);
		private:
	};

	namespace impl {
		struct ParameterParserFunctions {
			ParameterParser::fn_getLastError getLastError;
			ParameterParser::fn_getParamIndex getParamIndex;
			ParameterParser::fn_getParamValue getParamValue;
			ParameterParser::fn_getParamValueID getParamValueID;
		};
		extern ParameterParserFunctions* fn_ParameterParser;
	}
}