#pragma once

#include <array>
#include <fstream>
#include "Crypto.h"

namespace SHA3
{

class SHA3Hasher
{
public:
	static void Process(const Crypto::SHA3_Length sha3, std::ifstream& ifs, char* hash);
};

} // namespace SHA3
