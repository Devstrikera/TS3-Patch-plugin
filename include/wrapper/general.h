#pragma once

#include <cstddef>

namespace wrapper {
	class TSString {
		public:
			TSString(const char* buffer);
			TSString(const char* buffer, size_t length);

			explicit TSString(size_t length);
			~TSString();
		private:
			char* ptr;
			size_t length;
	};
}