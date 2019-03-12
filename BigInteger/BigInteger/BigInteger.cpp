// BigInteger.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include "BigInt.h"
#include <iostream>

int main()
{
	BigInt<uint32_t, uint64_t>();
	std::cout << "Hello World!\n";

	BigInt<uint8_t, uint16_t> test((uint16_t)12345);

	for (auto i = 0; i < 11; ++i)
	{
		test * BigInt<uint8_t, uint16_t>((uint16_t)721);
		std::cout << test.toHex().c_str() << std::endl;
	}

	/*BigInt<uint8_t, uint16_t> res((uint16_t)62208);

	for (auto i = 0; i < 21; ++i)
	{
		res * BigInt<uint8_t, uint16_t>((uint16_t)62208);
		std::cout << res.toHex().c_str() << std::endl;
	}*/
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
