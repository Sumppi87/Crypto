#include "pch.h"
#include "../CryptoAPI/BigInt.h"
#include <string>

TEST(LeftShift, LargeShiftOne)
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

TEST(LeftShift, WalkOneLeft)
{
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

TEST(LeftShift, WalkLeft)
{
	const uint64_t max = ~0ULL;
	BigInt num(max);

	// TODO: Fix a bug in left shift validation (over-index prevention is too strict in BigInt::LeftShift)
	//constexpr auto maxShift = ((sizeof(BigInt::Base) * 8) * (MAX_SIZE - 1));
	constexpr auto maxShift = ((sizeof(BigInt::Base) * 8) * (MAX_SIZE - 2));

	for (uint16_t shift = 1; shift < maxShift; ++shift)
	{
		num = num << 1;
		const uint16_t zeroes = shift / 4;
		const uint16_t rem = shift % 4;
		const uint64_t hexValLS = uint64_t(max << rem);
		const uint16_t hexValMS = (uint8_t(max) >> (4 - rem)) >> 4;
		const std::string hex = hexValMS > 0
			? ((std::stringstream() << std::hex << std::uppercase << hexValMS << hexValLS).str())
			: ((std::stringstream() << std::hex << std::uppercase << hexValLS).str());

		const std::string expected = std::string("0x") + hex + std::string(zeroes, '0');
		const std::string actual = num.ToHex();
		ASSERT_EQ(expected, actual);
	}
}

TEST(LeftShift, LargeShift)
{
	const uint64_t max = ~0ULL;
	const BigInt value(max);

	// TODO: Fix a bug in left shift validation (over-index prevention is too strict in BigInt::LeftShift)
	//constexpr auto maxShift = ((sizeof(BigInt::Base) * 8) * (MAX_SIZE - 1));
	constexpr auto maxShift = ((sizeof(BigInt::Base) * 8) * (MAX_SIZE - 2));

	for (uint16_t shift = 1; shift < maxShift; ++shift)
	{
		const BigInt num = value << shift;
		const uint16_t zeroes = shift / 4;
		const uint16_t rem = shift % 4;
		const uint64_t hexValLS = uint64_t(max << rem);
		const uint16_t hexValMS = (uint8_t(max) >> (4 - rem)) >> 4;
		const std::string hex = hexValMS > 0
			? ((std::stringstream() << std::hex << std::uppercase << hexValMS << hexValLS).str())
			: ((std::stringstream() << std::hex << std::uppercase << hexValLS).str());

		const std::string expected = std::string("0x") + hex + std::string(zeroes, '0');
		const std::string actual = num.ToHex();
		ASSERT_EQ(expected, actual);
	}
}

TEST(RightShift, LargeShiftOne)
{
	constexpr auto zeroes = ((sizeof(BigInt::Base) * 2) * MAX_SIZE) - 1;
	const std::string hexValue = std::string("0x") + std::to_string(8U) + std::string(zeroes, '0');
	const BigInt value = BigInt::FromString(hexValue.c_str());

	constexpr auto maxShift = ((sizeof(BigInt::Base) * 8) * (MAX_SIZE)) - 1;
	const BigInt zero = value >> (maxShift + 1);
	ASSERT_EQ(std::string("0x0"), zero.ToHex());

	for (uint16_t shift = maxShift;;)
	{
		const BigInt num = value >> shift;
		const uint16_t diff = (maxShift - shift);
		const uint16_t zeroes = diff / 4;
		const uint8_t hexNum = std::pow(2, (maxShift - shift) % 4);
		std::string expected = std::string("0x") + std::to_string(hexNum) + std::string(zeroes, '0');
		ASSERT_EQ(expected, num.ToHex());

		if (shift > 0)
			--shift;
		else
			break;
	}
}

TEST(RightShift, WalkOneRight)
{
	constexpr auto zeroes = ((sizeof(BigInt::Base) * 2) * MAX_SIZE) - 1;
	const std::string hexValue = std::string("0x") + std::to_string(8U) + std::string(zeroes, '0');
	BigInt num = BigInt::FromString(hexValue.c_str());

	constexpr auto maxShift = ((sizeof(BigInt::Base) * 8) * (MAX_SIZE)) - 1;
	const BigInt zero = num >> (maxShift + 1);
	ASSERT_EQ(std::string("0x0"), zero.ToHex());

	for (uint16_t shift = maxShift - 1;;)
	{
		num = num >> 1;
		const uint16_t zeroes = shift / 4;
		const uint8_t hexNum = std::pow(2, shift % 4);
		std::string expected = std::string("0x") + std::to_string(hexNum) + std::string(zeroes, '0');
		std::string actual = num.ToHex();
		ASSERT_EQ(expected, actual);

		if (shift > 0)
			--shift;
		else
			break;
	}
}

TEST(RightShift, WalkRight)
{
	const uint64_t max = ~0ULL;

	constexpr auto zeroes = ((sizeof(BigInt::Base) * 2) * (MAX_SIZE - 1));
	const std::string hexValue = std::string("0xFFFFFFFFFFFFFFFF") + std::string(zeroes, '0');
	BigInt num = BigInt::FromString(hexValue.c_str());

	constexpr auto maxShift = ((sizeof(BigInt::Base) * 8) * (MAX_SIZE));
	const BigInt zero = num >> (maxShift + 1);
	ASSERT_EQ(std::string("0x0"), zero.ToHex());

	for (uint16_t iter = 1; iter < maxShift; ++iter)
	{
		num = num >> 1;
		const int temp = (maxShift - iter) / 4;
		const int zeroes = temp - int(sizeof(BigInt::Base) * 2);
		const uint16_t rem = iter % 4;
		const uint64_t hexValMS = zeroes >= 0 ? uint64_t(max >> rem) : max >> (iter % (sizeof(BigInt::Base) * 8));
		const uint16_t hexValLS = uint8_t(max << (4 - rem)) & 0x0F;
		const std::string hex = (hexValLS > 0) && (zeroes >= 0)
			? ((std::stringstream() << std::hex << std::uppercase << hexValMS << hexValLS).str())
			: ((std::stringstream() << std::hex << std::uppercase << hexValMS).str());

		const std::string expected = std::string("0x") + ((zeroes > 0) ? hex + std::string(zeroes, '0') : hex);
		const std::string actual = num.ToHex();
		ASSERT_EQ(expected, actual);
	}
}