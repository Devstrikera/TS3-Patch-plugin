//
// Created by wolverindev on 11.05.18.
//

#include <include/wrapper/ParameterParser.h>
#include <iostream>

using namespace std;
using namespace wrapper;

impl::ParameterParserFunctions* impl::fn_ParameterParser = nullptr;

int ParameterParser::getLastError() {
	return impl::fn_ParameterParser->getLastError(this);
}

int ParameterParser::getParamIndex(const TSString &key, int& index) {
	int local_index = 0; //If we use a ref it sometimes cause a sigfault.... unknown why :D
	auto result = impl::fn_ParameterParser->getParamIndex(this, key, local_index);
	index = local_index;
	return result;
}

int ParameterParser::getParamValueID(const TSString &key, int &index) {
	return impl::fn_ParameterParser->getParamValueID(this, key, index);
}

std::string ParameterParser::getParamValue(const TSString &key, int &index) {
	std::string response;
	impl::fn_ParameterParser->getParamValue(response, this, key, index);
	return response;
}

bool ParameterParser::hasParam(const TSString &key) {
	int index = 0;
	auto value = this->getParamValue(key, index);
	return this->getLastError() == 0;
	//return this->getParamIndex(key, index) > 0;
}