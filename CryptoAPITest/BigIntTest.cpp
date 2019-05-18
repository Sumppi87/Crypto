#include "pch.h"
#include "../CryptoAPI/BigInt.h"
#include <string>

TEST(LeftShift, LargeShift)
{
	const BigInt one(1);
	constexpr auto maxShift = ((sizeof(BigInt::Base) * 8) * (MAX_SIZE - 1));
	for (uint16_t shift = 0; shift < maxShift; ++shift)
	{
		const BigInt num = one << shift;
		const uint16_t zeroes = shift / 4;
		const uint8_t hexNum = std::pow(2, shift % 4);
		std::string expected = std::string("0x") + std::to_string(hexNum) + std::string(zeroes, '0');
		ASSERT_EQ(expected, num.ToHex());
	}
}

TEST(LeftShift, WalkLeft)
{
	EXPECT_EQ(1, 1);
	EXPECT_TRUE(true);

	BigInt num(1);
	constexpr auto maxShift = ((sizeof(BigInt::Base) * 8) * (MAX_SIZE - 1));
	for (uint16_t shift = 1; shift < maxShift; ++shift)
	{
		num = num << 1;
		const uint16_t zeroes = shift / 4;
		const uint8_t hexNum = std::pow(2, shift % 4);
		std::string expected = std::string("0x") + std::to_string(hexNum) + std::string(zeroes, '0');
		ASSERT_EQ(expected, num.ToHex());
	}
}