#include "BigInt.h"
#include "CryptoUtils.h"
#include "TaskManager.h"
#include <type_traits>
#include <string>
#include <cstdlib>
#include <algorithm>
#include <iostream>
#include <vector>
#include <intrin.h>
#include <immintrin.h>
#include <algorithm>

namespace
{
	// How many iterations to perform when testing whether a value is a prime or not
	// With 60, a chance for a false positive is 1 / (2^128)
	const uint8_t PRIME_TEST_ITERATIONS = 60U;

	const unsigned char BASE_BITS = sizeof(BigInt::Base) * 8U;

	char NumToChar(const uint8_t num, const bool isHex)
	{
		switch (num)
		{
		case 0U:
			return '0';
		case 1U:
			return '1';
		case 2U:
			return '2';
		case 3U:
			return '3';
		case 4U:
			return '4';
		case 5U:
			return '5';
		case 6U:
			return '6';
		case 7U:
			return '7';
		case 8U:
			return '8';
		case 9U:
			return '9';
		default:
			if (!isHex)
				throw std::invalid_argument("Not a valid decimal number");
			switch (num)
			{
			case 10U:
				return 'A';
			case 11U:
				return 'B';
			case 12U:
				return 'C';
			case 13U:
				return 'D';
			case 14U:
				return 'E';
			case 15U:
				return 'F';
			default:
				throw std::invalid_argument("Not a valid hexadecimal");
			}
		}
	}

	uint8_t CharToNum(const char c, const bool isHex)
	{
		switch (c)
		{
		case '0':
			return 0U;
		case '1':
			return 1U;
		case '2':
			return 2U;
		case '3':
			return 3U;
		case '4':
			return 4U;
		case '5':
			return 5U;
		case '6':
			return 6U;
		case '7':
			return 7U;
		case '8':
			return 8U;
		case '9':
			return 9U;
		default:
			if (!isHex)
				throw std::invalid_argument("Not a valid decimal number");
			switch (c)
			{
			case 'A':
				return 10U;
			case 'B':
				return 11U;
			case 'C':
				return 12U;
			case 'D':
				return 13U;
			case 'E':
				return 14U;
			case 'F':
				return 15U;
			default:
				throw std::invalid_argument("Not a valid hexadecimal");
				break;
			}
		}
	}

	inline void AddResult(uint64_t* src, const uint64_t val)
	{
		if (_addcarry_u64(0U, val, *src, src))
		{
			AddResult(src + 1U, 1U);
		}
	};

	inline void SubResult(uint64_t* src, const uint64_t val, const unsigned char carry)
	{
		if (_subborrow_u64(carry, *src, val, src))
		{
			SubResult(src + 1U, 0U, 1U);
		}
	};

	inline void* GetShiftedPtr(uint64_t* basePtr, const unsigned char shift)
	{
		char* p = reinterpret_cast<char*>(basePtr);
		p += shift;
		return p;
	}

	inline const void* GetShiftedPtr(const uint64_t* basePtr, const unsigned char shift)
	{
		const char* p = reinterpret_cast<const char*>(basePtr);
		p += shift;
		return p;
	}
}

BigInt::ValueContainer::ValueContainer()
	: m_vals{}
	, m_currentSize(1)
{
	m_vals[0U] = 0U;
}

void BigInt::ValueContainer::SetZero()
{
	memset(m_vals, 0U, m_currentSize * sizeof(Base));
	m_currentSize = 1U;
	m_vals[0U] = 0U;
}

void BigInt::ValueContainer::CleanPreceedingZeroes()
{
	for (auto i = m_currentSize - 1U; i > 0U; --i)
	{
		if (m_vals[i] == 0U)
		{
			m_currentSize--;
		}
		else
		{
			break;
		}
	}
}

BigInt::Base& BigInt::ValueContainer::operator[](const size_t index)
{
#if defined(_DEBUG) || defined(DEBUG_MEM_ACCESS)
	_STL_VERIFY(index < m_currentSize, "index out of range");
#endif
	return m_vals[index];
}

const BigInt::Base& BigInt::ValueContainer::operator[](const size_t index) const
{
#if defined(_DEBUG) || defined(DEBUG_MEM_ACCESS)
	_STL_VERIFY(index < m_currentSize, "index out of range");
#endif
	return m_vals[index];
}

BigInt::ValueContainer::operator void*()
{
	return (void*)m_vals;
}

BigInt::ValueContainer::operator const void*() const
{
	return (const void*)m_vals;
}

BigInt::ValueContainer::operator char*()
{
	return (char*)m_vals;
}

BigInt::ValueContainer::operator const char*() const
{
	return (const char*)m_vals;
}

BigInt::ValueContainer::operator uint64_t*()
{
	return m_vals;
}

BigInt::ValueContainer::operator const uint64_t*() const
{
	return m_vals;
}

/*static*/
BigInt BigInt::FromRawData(const char* data, const size_t length)
{
	BigInt res;

	res.Resize((length / sizeof(Base)) + (length % sizeof(Base) > 0U ? 1U : 0U));
	memcpy(&res.m_vals, data, length);

	return res;
}

BigInt BigInt::FromString(const char* input)
{
	return BigInt().ParseStrInput(input);
}

BigInt& BigInt::ParseStrInput(const char* input)
{
	if (input == nullptr)
	{
		throw std::invalid_argument("Not a valid input");
	}
	auto length = strlen(input);
	if (length < 1U)
	{
		throw std::invalid_argument("Not a valid input");
	}
	if (input[0U] == '-')
	{
		// It's a negative number
		++input;
		--length;
		m_sign = Sign::NEG;
	}

	if (length > 2U && input[0U] == '0' && input[1U] == 'x')
	{
		input += 2U;
		FromBase16(input);
	}
	else
	{
		FromBase10(input);
	}
	CleanPreceedingZeroes();
	return *this;
}

void BigInt::FromBase10(const char* input)
{
	if (input == nullptr)
	{
		throw std::invalid_argument("Not a valid decimal");
	}
	auto length = strlen(input);
	if (length < 1U)
	{
		throw std::invalid_argument("Not a valid decimal");
	}

	const BigInt ten(10U);

	for (size_t i = 0U; i < length; ++i)
	{
		BigInt digit;
		digit.m_vals[0U] = CharToNum(input[i], false);
		*this = *this * ten;
		*this = *this + digit;
	}
}

void BigInt::FromBase16(const char* hex)
{
	if (hex == nullptr)
	{
		throw std::invalid_argument("Not a valid hexadecimal");
	}
	auto length = strlen(hex);
	if (length < 1U)
	{
		throw std::invalid_argument("Not a valid hexadecimal");
	}

	const size_t neededSize = length / (sizeof(Base) * 2U) + ((length % (sizeof(Base) * 2U)) > 0U ? 1U : 0U);
	Resize(neededSize);

	for (size_t i = length - 1U;; --i)
	{
		const size_t index = ((length - 1U) - i) / (sizeof(Base) * 2U);
		const size_t shift = (((length - 1U) - i) % (sizeof(Base) * 2U)) * 4U;
		const Base val = CharToNum(hex[i], true);
		const Base shifted = (val << shift);
		m_vals[index] += shifted;
		if (i == 0U)
		{
			break;
		}
	}
}

BigInt::BigInt()
	: m_sign(Sign::POS)
{
}

BigInt::BigInt(const Base* data, const size_t currentSize)
	: m_sign(Sign::POS)
{
	CopyFromSrc(data, currentSize, 0U);
}

BigInt::BigInt(const uint8_t val)
	: m_sign(Sign::POS)
{
	FromNum(val, sizeof(uint8_t));
}

BigInt::BigInt(const uint16_t val)
	: m_sign(Sign::POS)
{
	FromNum(val, sizeof(uint16_t));
}

BigInt::BigInt(const uint32_t val)
	: m_sign(Sign::POS)
{
	FromNum(val, sizeof(uint32_t));
}

BigInt::BigInt(const uint64_t val)
	: m_sign(Sign::POS)
{
	FromNum(val, sizeof(uint64_t));
}

BigInt::BigInt(const int val)
	: m_sign(val < 0 ? Sign::NEG : Sign::POS)
{
	FromNum(val < 0 ? uint32_t(-val) : (uint32_t)val, sizeof(uint32_t));
}

BigInt::BigInt(const int64_t val)
	: m_sign(val < 0U ? Sign::NEG : Sign::POS)
{
	FromNum(val < 0 ? uint64_t(-val) : (uint64_t)val, sizeof(uint64_t));
}

BigInt::BigInt(const char* input)
	: m_sign(Sign::POS)
{
	ParseStrInput(input);
}

BigInt BigInt::operator+(const BigInt& other) const
{
	if (other.IsZero())
	{
		return *this;
	}
	else if (IsPositive() == other.IsPositive())
	{
		// Both have the same sign, so no sign change -> just sum them
		BigInt sum = SumWithoutSign(other);
		sum.m_sign = m_sign;
		return sum;
	}
	else
	{
		// Values have different signs -> Sign might change
		const Comparison c = CompareWithoutSign(other);
		if (c == Comparison::EQUAL)
		{
			// Result is always zero
			return BigInt(0U);
		}
		else
		{
			// *this is bigger
			if (c == Comparison::GREATER)
			{
				// As *this is bigger, substract 'other' from *this
				BigInt res = SubstractWithoutSign(other);

				// Resulting sign is comes always from *this
				//  1) -20 + 15 = -5
				//  2) 20 - 15 = 5
				res.m_sign = m_sign;
				return res;
			}
			else
			{
				// As other is bigger, substract *this from 'other'
				BigInt res = other.SubstractWithoutSign(*this);

				// Resulting sign is comes always from 'other'
				//  1) 15 - 20 = -5
				//  2) -15 + 20 = 5
				res.m_sign = other.m_sign;
				return res;
			}
		}
	}
}

BigInt BigInt::operator-(const BigInt& other) const
{
	if (other.IsZero())
	{
		return *this;
	}
	else if (IsZero())
	{
		// *this is zero, just flip the sign of 'other'
		BigInt res(other);

		// 'other' is positive -> result is negative and wise-versa
		res.m_sign = other.IsPositive() ? Sign::NEG : Sign::POS;
		return res;
	}
	else if (IsPositive() ^ other.IsPositive()) // Check with XOR that signs are not the same
	{
		// Values can be summed as
		// 1) *this is positive and 'other' is negative (e.g. 17 - (-9) = 26)
		//  -> Sum the values and sign is Sign::POS
		// 2) *this is negative and 'other' is positive (e.g. -17 - 9 = -26)
		// -> Sum the values and and sign is Sign::NEG
		BigInt res = SumWithoutSign(other);
		res.m_sign = IsPositive() ? Sign::POS : Sign::NEG;
		return res;
	}
	else
	{
		// Signs are the same
		const Comparison c = CompareWithoutSign(other);
		if (c == Comparison::EQUAL)
		{
			// Absolute values are the same -> Always zero as sign is the same
			// 1) Signs are negative: -17 - (-17) = -17 + 17 = 0
			// 2) Signs are positive: 17 - 17 = 0
			return BigInt(0);
		}
		else if (c == Comparison::GREATER)
		{
			// *this is bigger -> Always decrement from *this and set the sign from *this
			// 1) Signs are negative: -20 - (-5) = -20 + 5 = -15
			// 2) Signs are positive: 20 - 5 = 15
			BigInt res = SubstractWithoutSign(other);
			res.m_sign = m_sign;
			return res;
		}
		else
		{
			// *this is smaller -> Always decrement from 'other' and set the sign flipped
			// 1) Signs are negative: -5 - (-20) = -5 + 20 = 15
			// 2) Signs are positive: 5 - 20 = -15
			BigInt res = other.SubstractWithoutSign(*this);
			res.m_sign = IsPositive() ? Sign::NEG : Sign::POS;
			return res;
		}
	}
}

BigInt BigInt::operator%(const BigInt& other) const
{
	if (other.IsZero())
	{
		throw std::invalid_argument("Division by zero");
	}
	else if (CompareWithoutSign(other) == Comparison::LESSER)
	{
		// Not strictly how C++ behaves... (%-operator can return negative numbers)
		BigInt rem(*this);
		rem.m_sign = Sign::POS;
		return rem;
	}

	BigInt remainder;
	Div(other, remainder, nullptr);
	remainder.m_sign = Sign::POS;
	return remainder;
}

BigInt BigInt::operator/(const BigInt& other) const
{
	uint64_t base = 0U;
	if (other.IsZero())
	{
		throw std::invalid_argument("Division by zero");
	}
	else if (other.IsOne())
	{
		BigInt res(*this);

		// When signs are the same, result is always positive, otherwise negative
		res.m_sign = IsPositive() == other.IsPositive() ? Sign::POS : Sign::NEG;
		return res;
	}
	else if (other.IsBase2(base))
	{
		// If the divisor is base-2, a simple shift will do
		BigInt quotient = *this >> base;
		quotient.m_sign = IsPositive() == other.IsPositive() ? Sign::POS : Sign::NEG;
		return quotient;
	}

	BigInt remainder;
	BigInt quot;
	Div(other, remainder, &quot);
	quot.m_sign = IsPositive() == other.IsPositive() ? Sign::POS : Sign::NEG;

	return quot;
}

BigInt BigInt::operator*(const BigInt& other) const
{
	uint64_t base = 0U;
	if (IsZero() || other.IsZero())
	{
		return BigInt();
	}
	else if (IsOne())
	{
		BigInt res(other);

		// When signs are the same, result is always positive, otherwise negative
		res.m_sign = IsPositive() == other.IsPositive() ? Sign::POS : Sign::NEG;
		return res;
	}
	else if (other.IsOne())
	{
		BigInt res(*this);

		// When signs are the same, result is always positive, otherwise negative
		res.m_sign = IsPositive() == other.IsPositive() ? Sign::POS : Sign::NEG;
		return res;
	}
	else if (other.IsBase2(base))
	{
		// If the divisor is base-2, a simple shift will do
		BigInt res = *this << base;

		// When sigsn are the same, result is always positive, otherwise negative
		res.m_sign = IsPositive() == other.IsPositive() ? Sign::POS : Sign::NEG;
		return res;
	}
	else
	{
		const auto neededSize = CurrentSize() + other.CurrentSize();
		BigInt res;

		// When sigsn are the same, result is always positive, otherwise negative
		res.m_sign = IsPositive() == other.IsPositive() ? Sign::POS : Sign::NEG;
		res.Resize(neededSize);

		#pragma loop(no_vector)
		for (size_t i = 0U; i < CurrentSize(); ++i)
		{
			#pragma loop(no_vector)
			for (size_t ii = 0U; ii < other.CurrentSize(); ++ii)
			{
				Base carry = 0U;
				const Base mul = _umul128(m_vals[i], other.m_vals[ii], &carry);
				AddResult(&res.m_vals[i + ii], mul);
				if (carry)
					AddResult(&res.m_vals[i + ii + 1], carry);
			}
		}

		res.CleanPreceedingZeroes();
		return res;
	}
}

BigInt BigInt::PowMod(const BigInt& exp, const BigInt& mod) const
{
	if (!exp.IsPositive())
	{
		throw std::logic_error("Exponent must be positive number!");
	}

	BigInt e = exp;
	BigInt base = *this;
	BigInt copy = BigInt(1U);
	copy.m_sign = (IsPositive() || !exp.IsOdd()) ? Sign::POS : Sign::NEG;
	uint64_t shift = 0U;

	Base tmpBuf[MAX_SIZE] = {};
	Base* tmpBuffer = tmpBuf;
	auto Mul = [tmpBuffer](BigInt& multiplied, const BigInt& multiplier)
	{
		const auto neededSize = multiplied.CurrentSize() + multiplier.CurrentSize();

		// When signs are the same, result is always positive, otherwise negative
		multiplied.m_sign = multiplied.IsPositive() == multiplier.IsPositive() ? Sign::POS : Sign::NEG;
		multiplied.Resize(neededSize);

		#pragma loop(no_vector)
		for (size_t i = 0U; i < multiplied.CurrentSize(); ++i)
		{
			#pragma loop(no_vector)
			for (size_t ii = 0U; ii < multiplier.CurrentSize(); ++ii)
			{
				Base carry = 0U;
				const Base mul = _umul128(multiplied.m_vals[i], multiplier.m_vals[ii], &carry);
				AddResult(&tmpBuffer[i + ii], mul);
				if (carry)
					AddResult(&tmpBuffer[i + ii + 1U], carry);
			}
		}
		multiplied.CopyFromSrc(tmpBuffer, neededSize, 0U);
		memset(tmpBuffer, 0U, sizeof(Base) * neededSize);
		multiplied.CleanPreceedingZeroes();
	};

	while (!e.IsZero())
	{
		if (e.IsOdd())
		{
			Mul(copy, base);
			Mod(copy, mod);
		}

		RightShift(e, exp, ++shift);

		Mul(base, base);
		Mod(base, mod);
	}
	return copy;
}

BigInt BigInt::Pow(const BigInt& exp) const
{
	if (!exp.IsPositive())
	{
		throw std::logic_error("Exponent must be positive number!");
	}

	BigInt e = exp;
	BigInt base = *this;
	BigInt copy = BigInt(1U);
	copy.m_sign = (IsPositive() || !exp.IsOdd()) ? Sign::POS : Sign::NEG;

	while (!e.IsZero())
	{
		if (e.IsOdd())
		{
			copy = copy * base;
		}

		e = e >> 1U;
		base = base * base;
	}
	return copy;
}

BigInt BigInt::operator<<(const uint64_t shift) const
{
	BigInt copy;
	LeftShift(copy, *this, shift);
	return copy;
}

void BigInt::LeftShift(BigInt& res, const BigInt& target, const uint64_t shift)
{
	if (target.IsZero())
	{
		res = BigInt();
		return;
	}
	else if (shift == 0U)
	{
		res = target;
		return;
	}

	// Inherits the sign from target
	res.m_sign = target.m_sign;
	memset(res.m_vals, 0U, sizeof(Base) * res.CurrentSize());

	const uint64_t quot = (shift / BASE_BITS);
	const unsigned char rem = (shift % (BASE_BITS));

	if ((quot + target.CurrentSize() + (rem > 0U ? 1U : 0U)) > MAX_SIZE)
	{
		throw std::invalid_argument("Overflow detected");
	}
	else if (rem == 0U)
	{
		// Add elements by the given quotient
		res.Resize(quot + target.CurrentSize());

		// Simpler case, just add elements after added zeroes
		res.CopyFromSrc(&target.m_vals[0U], target.CurrentSize(), quot);
		res.CleanPreceedingZeroes();
	}
	else if (rem % 8 == 0)
	{
		const unsigned char bytesToShift = rem / 8U;
		const auto currSize = target.CurrentSize();
		res.Resize(quot + currSize + 1);

		const void* src = &target.m_vals[0U];
		void* dst = GetShiftedPtr(&res.m_vals[quot], bytesToShift);
		auto count = currSize * sizeof(Base);
		memcpy(dst, src, count);
		res.CleanPreceedingZeroes();
	}
	else
	{
		const auto currSize = target.CurrentSize();
		res.Resize(quot + currSize + 1U);

		// As a optimization, do the "special cases" outside the for-loop
		// It has a measurable impact on performance to _not_ have any if-conditions in the loop
		res.m_vals[size_t(quot)] = __ll_lshift(target.m_vals[0U], rem);
		res.m_vals[currSize + size_t(quot)] = __shiftleft128(target.m_vals[currSize - 1U], 0U, rem);

		#pragma loop(no_vector)
		for (size_t i = 1U; i < currSize; ++i)
		{
			res.m_vals[i + size_t(quot)] = __shiftleft128(target.m_vals[i - 1U], target.m_vals[i], rem);
		}

		res.CleanPreceedingZeroes();
	}
}

BigInt BigInt::operator>>(const uint64_t shift) const
{
	// Inherits the sign from *this
	BigInt copy;
	RightShift(copy, *this, shift);
	return copy;
}

void BigInt::RightShift(BigInt& res, const BigInt& target, const uint64_t shift)
{
	if (target.IsZero())
	{
		res = BigInt();
		return;
	}
	else if (shift == 0U)
	{
		res = target;
		return;
	}
	else if (shift >= (target.CurrentSize() * BASE_BITS))
	{
		// A quick cursoly check if shift definately bigger than 'target'
		// More detailed check is done by checking the actual bit-count if this check is passed
		res = BigInt();
		return;
	}

	// Inherits the sign from 'target'
	res.m_sign = target.m_sign;

	const auto quot = (shift / (BASE_BITS));
	const unsigned char rem = (shift % (BASE_BITS));

	const uint64_t width = target.GetBitWidth();
	if (shift >= width)
	{
		res = BigInt();
		return;
	}
	else if (rem == 0U)
	{
		// Simpler case, just drop elements from the start

		res.Resize(target.CurrentSize() - quot);
		res.CopyFromSrc(&target.m_vals[quot], target.CurrentSize() - quot, 0U);
		res.CleanPreceedingZeroes();
	}
	else if (rem % 8U == 0U)
	{
		const unsigned char bytesToShift = rem / 8U;
		const auto currSize = target.CurrentSize();
		res.Resize(currSize - quot);

		const void* src = GetShiftedPtr(&target.m_vals[quot], bytesToShift);
		void* dst = &res.m_vals[0U];
		auto count = (currSize * sizeof(Base)) - bytesToShift;
		memcpy(dst, src, count);
		res.CleanPreceedingZeroes();
	}
	else
	{
		res.Resize(target.CurrentSize() - quot);

		const auto maxIndex = target.CurrentSize() - 1;
		#pragma loop(no_vector)
		for (size_t i = size_t(quot); i < maxIndex; ++i)
		{
			res.m_vals[i - size_t(quot)] = __shiftright128(target.m_vals[i], (i + 1U) < target.CurrentSize() ? target.m_vals[i + 1U] : 0U, rem);
		}
		res.m_vals[maxIndex - quot] = __shiftright128(target.m_vals[maxIndex], 0U, rem);

		res.CleanPreceedingZeroes();
	}
}

bool BigInt::operator>(const BigInt& other) const
{
	const Comparison c = CompareWithSign(other);
	return c == Comparison::GREATER;
}

bool BigInt::operator>=(const BigInt& other) const
{
	const Comparison c = CompareWithSign(other);
	return c == Comparison::GREATER || c == Comparison::EQUAL;
}

bool BigInt::operator<=(const BigInt& other) const
{
	const Comparison c = CompareWithSign(other);
	return c == Comparison::LESSER || c == Comparison::EQUAL;
}

bool BigInt::operator<(const BigInt& other) const
{
	const Comparison c = CompareWithSign(other);
	return c == Comparison::LESSER;
}

bool BigInt::operator!=(const BigInt& other) const
{
	const Comparison c = CompareWithSign(other);
	return !(c == Comparison::EQUAL);
}

bool BigInt::operator==(const BigInt& other) const
{
	const Comparison c = CompareWithSign(other);
	return c == Comparison::EQUAL;
}

std::string BigInt::ToHex() const
{
	if (IsZero())
	{
		return "0x0";
	}

	std::string ret;
	if (!IsPositive())
	{
		ret += '-';
	}

	ret.append("0x");
	bool nonZeroAdded = false;
	#pragma loop(no_vector)
	for (size_t i = CurrentSize() - 1U;; --i)
	{
		#pragma loop(no_vector)
		for (auto nibbleNro = (sizeof(Base) * 2U) - 1U;; --nibbleNro)
		{
			const auto mask = (Base(0xF) << (nibbleNro * 4));
			const auto nibble = Base(m_vals[i] & mask) >> (nibbleNro * 4U);
			if (!nonZeroAdded && nibble == 0U)
			{
				continue;
			}
			nonZeroAdded = true;
			ret += NumToChar(nibble > UINT8_MAX ? UINT8_MAX : uint8_t(nibble), true);

			if (nibbleNro == 0U)
				break;
		}
		if (i == 0U)
			break;
	}
	if (!nonZeroAdded)
	{
		ret += NumToChar(0U, true);
	}
	return ret;
}

std::string BigInt::ToDec() const
{
	if (IsZero())
	{
		return "0";
	}

	// Maybe just a bit lazy, but it's easy to convert from hex to dec...
	std::string hex = ToHex();
	if (!IsPositive())
	{
		hex.erase(hex.begin(), hex.begin() + 3U);
	}
	else
	{
		hex.erase(hex.begin(), hex.begin() + 2U);
	}

	std::vector<unsigned int> dec;
	for (const char c : hex)
	{
		unsigned int carry = CharToNum(c, true);

		for (auto i = 0U; i < dec.size(); ++i)
		{
			auto val = dec[i] * 16U + carry;
			dec[i] = val % 10U;
			carry = val / 10U;
		}
		while (carry > 0U)
		{
			dec.push_back(carry % 10U);
			carry /= 10U;
		}
	}

	std::string ret;
	if (!IsPositive())
	{
		ret += '-';
	}
	for (auto iter = dec.rbegin(); iter != dec.rend(); ++iter)
	{
		const auto c = *iter;
		ret += NumToChar(c > UINT8_MAX ? UINT8_MAX : uint8_t(c), false);
	}

	return ret;
}

std::string BigInt::ToRawData() const
{
	std::string ret;

	for (size_t i = 0U; i < CurrentSize(); ++i)
	{
		for (size_t charPos = 0U; charPos < sizeof(Base); ++charPos)
		{
			const Base mask = (Base(0xFF) << (charPos * 8U));
			const auto shift = (charPos * 8U);
			Base c = Base(m_vals[i] & mask);
			c = (c >> shift);

			if (i == (CurrentSize() - 1U)
				&& c == 0U)
			{
				// The last element may contain null's, depending on source data and sizeof(Base)
				continue;
			}
			ret += char(c);
		}
	}

	return ret;
}

bool BigInt::IsZero() const
{
	if (CurrentSize() == 0U
		|| (CurrentSize() == 1U
			&& m_vals[0U] == 0))
	{
		return true;
	}
	return false;
}

bool BigInt::IsOne() const
{
	return (CurrentSize() == 1U && m_vals[0U] == 1U);
}

bool BigInt::IsOdd() const
{
	if (IsZero())
	{
		return false;
	}
	return (m_vals[0U] & 1U) == 1U;
}

bool BigInt::IsPositive() const
{
	return m_sign == Sign::POS;
}

BigInt BigInt::GreatestCommonDivisor(const BigInt& other, uint64_t& iters) const
{
	BigInt copy(*this);
	BigInt div(other);
	while (true)
	{
		++iters;
		if (div.IsZero())
		{
			return copy;
		}

		copy = copy % div;
		if (copy.IsZero())
		{
			return div;
		}
		div = div % copy;
	}
}

BigInt BigInt::ModuloMultiplicativeInverse(const BigInt& M) const
{
	// Assumes that *this and M are co-prime
	// Returns multiplicative modulo inverse of *this under M

	// Find gcd using Extended Euclid's Algorithm
	BigInt gcd, x, y;
	ExtendedEuclididan(M, gcd, x, y);

	// In case x is negative, we handle it by adding extra M
	// Because we know that multiplicative inverse of A in range M lies
	// in the range [0, M-1]
	if (!x.IsPositive())
	{
		x = x + M;
	}

	return x;
}

void BigInt::ExtendedEuclididan(const BigInt& b, BigInt& gcd, BigInt& x, BigInt& y) const
{
	BigInt a(*this);

	BigInt s(0);
	BigInt old_s(1U);
	BigInt t(1U);
	BigInt old_t(0U);
	BigInt r(b);
	BigInt old_r(a);

	while (!r.IsZero())
	{
		BigInt quotient = old_r / r;

		// We are overriding the value of r, before that we store it's current
		// value in temp variable, later we assign it to old_r
		BigInt temp(r);
		r = old_r - quotient * r;
		old_r = temp;

		// We treat s and t in the same manner we treated r
		temp = s;
		s = old_s - quotient * s;
		old_s = temp;

		temp = t;
		t = old_t - quotient * t;
		old_t = temp;
	}

	gcd = old_r;
	x = old_s;
	y = old_t;
}
/*
Input #1: n > 3, an odd integer to be tested for primality
Input #2: k, the number of rounds of testing to perform
Output: "composite" if n is found to be composite, "probably prime" otherwise

write n as 2^r*d + 1 with d odd (by factoring out powers of 2 from n - 1)
WitnessLoop: repeat k times:
   pick a random integer a in the range [2, n - 2]
   x = a^d mod n
   if x == 1 or x == n - 1 then
	  continue WitnessLoop
   repeat r - 1 times:
	  x = x^2 mod n
	  if x == n - 1 then
		 continue WitnessLoop
   return "composite"
return "probably prime"
*/
bool BigInt::IsPrimeNumber() const
{
	if (IsZero() || !IsOdd())
		return false;
	else if (*this == 3U)
		return true;

	std::atomic<uint8_t> iters(0U);
	bool isPrime = true;

#ifdef USE_THREADS
	std::function<void()> f = std::bind(&BigInt::IsPrimeNumberPriv, this, &iters, &isPrime);
	TaskManager::ExecuteFunction(f);
#else
	IsPrimeNumberPriv(&iters, &isPrime);
#endif
	return isPrime;
}

void BigInt::IsPrimeNumberPriv(std::atomic<uint8_t>* iters, bool* pIsPrime) const
{
	CryptoUtils::RandomGenerator rand_gen;

	const BigInt& n = *this;
	const BigInt n_1 = *this - 1U;
	const BigInt n_3 = *this - 3U;
	const size_t r = n_1.GetLSB();
	const BigInt d = n_1 / BigInt(2U).Pow(r);

	auto InnerLoop = [r, &n_1, &n](BigInt& x)
	{
		// Repeat r - 1 times
		for (auto ii = 1U; ii < r; ++ii)
		{
			x = x.PowMod(2U, n);
			if (x == n_1)
			{
				return true;
			}
		}
		return false;
	};

	while (*pIsPrime)
	{
		auto i = (*iters)++;
		if (i >= PRIME_TEST_ITERATIONS)
			break;
		BigInt a;

		// Pick a size for 'a' between one and CurrentSize of this
		auto size = (rand_gen.Random64() % CurrentSize()) + 1U;
		a.Resize(size);
		rand_gen.RandomData((uint64_t*)a.m_vals, a.CurrentSize());
		a = (a % n_3) + 2U;

		BigInt x = a.PowMod(d, *this);
		if (x.IsOne() || x == n_1)
		{
			continue;
		}

		if (InnerLoop(x))
			continue;

		*pIsPrime = false;
	}
}

void BigInt::Div(const BigInt& div, BigInt& rem, BigInt* pQuot /*= nullptr*/) const
{
	if (IsZero())
	{
		throw std::invalid_argument("Division by zero");
	}

	rem = BigInt(*this);
	rem.m_sign = Sign::POS; // Remainder is _always_ positive

	if (pQuot)
	{
		*pQuot = BigInt(0);

		// When the signs are same, quotient is always positive, otherwise negative
		//  1) 10 / 5 = 2
		//  2) -10 / -5 = 2
		//  3) 10  / -5 = -2
		//  4) -10 / 5 = -2
		pQuot->m_sign = IsPositive() == div.IsPositive() ? Sign::POS : Sign::NEG;
	}

	BigInt divisor;
	const uint64_t divBitCount = div.GetBitWidth();
	// Loop until the absolute value of divisor is smaller than remainder
	while (div.CompareWithoutSign(rem) != Comparison::GREATER)
	{
		uint64_t shift = rem.GetBitWidth() - divBitCount;
		if (div.MostSignificant() > rem.MostSignificant())
		{
			shift--;
		}
		LeftShift(divisor, div, shift);

		while (divisor.CompareWithoutSign(rem) == Comparison::GREATER)
		{
			divisor = divisor >> 1U;
			--shift;
		}

		if (pQuot)
		{
			pQuot->SetBit(shift);
		}

		SubstractWithoutSign(rem, divisor);
	}
}

void BigInt::CleanPreceedingZeroes()
{
	m_vals.CleanPreceedingZeroes();
}

void BigInt::SetBit(const uint64_t bitNo)
{
	const uint64_t elementNo = (bitNo / (BASE_BITS));
	const size_t bitNoInElement = (bitNo % (BASE_BITS));

	if (elementNo >= CurrentSize())
	{
		// Size needs to be increased
		// elementNo is an index starting from 0 -> add 1
		Resize(elementNo + 1U);
	}

	m_vals[size_t(elementNo)] |= (Base(1U) << bitNoInElement);
}

uint64_t BigInt::GetBitWidth() const
{
	if (!IsZero())
	{
		uint64_t count = (CurrentSize() - 1U) * (BASE_BITS);
		unsigned long index = 0U;
		if (_BitScanReverse64(&index, m_vals[CurrentSize() - 1U]))
		{
			count += (1U + index);
		}
		return count;
	}
	return 0U;
}

uint64_t BigInt::GetByteWidth() const
{
	const uint64_t bits = GetBitWidth();
	return (bits / 8U) + ((bits % 8U) > 0U ? 1U : 0U);
}

bool BigInt::IsBase2(uint64_t& base) const
{
	uint64_t t = 0U;
	if (IsZero())
	{
		return false;
	}

	bool bitFound = false;
	for (size_t i = 0U; i < CurrentSize(); ++i)
	{
		const Base v = m_vals[i];
		unsigned long f = 0U;
		unsigned long r = 0U;
		if (_BitScanForward64(&f, v)
			&& _BitScanReverse64(&r, v))
		{
			if (bitFound || r != f)
			{
				return false;
			}
			bitFound = true;
			t += f;
		}
		else if (!bitFound)
		{
			// Current value has not bit (i.e. is zero)
			t += BASE_BITS;
		}
	}
	base = bitFound ? t : 0U;
	return bitFound;
}

void BigInt::SetZero()
{
	m_sign = Sign::POS;
	m_vals.SetZero();
}

size_t BigInt::CurrentSize() const
{
	return m_vals.m_currentSize;
}

void BigInt::FromNum(const uint64_t val, const uint8_t size)
{
	const size_t chunks = size / sizeof(Base);
	Resize(chunks == 0U ? 1U : chunks);
	for (size_t i = 0U; i < CurrentSize(); ++i)
	{
		const auto shift = BASE_BITS * i;
		m_vals[i] = Base(val >> shift);
	}
	CleanPreceedingZeroes();
}

BigInt BigInt::SumWithoutSign(const BigInt& other) const
{
	BigInt copy;
	const auto s = std::max(other.CurrentSize(), CurrentSize()) + 1U;

	copy.Resize(s);
	const size_t size = CurrentSize();
	const size_t size2 = other.CurrentSize();

	#pragma loop(no_vector)
	for (size_t i = 0U; i < s; ++i)
	{
		const Base val1 = i < size ? m_vals[i] : 0U;
		const Base val2 = i < size2 ? other.m_vals[i] : 0U;

		Base sum = 0U;
		if (_addcarry_u64(0U, val1, val2, &sum))
			AddResult(&copy.m_vals[i + 1U], 1U);
		AddResult(&copy.m_vals[i], sum);
	}

	copy.CleanPreceedingZeroes();
	return copy;
}

BigInt BigInt::SubstractWithoutSign(const BigInt& other) const
{
	BigInt copy(*this);
	const size_t size = std::min(CurrentSize(), other.CurrentSize());
	#pragma loop(no_vector)
	for (size_t i = 0U; i < size; ++i)
	{
		const Base val = other.m_vals[i];
		SubResult(&copy.m_vals[i], val, 0U);
	}
	copy.CleanPreceedingZeroes();
	return copy;
}

void BigInt::Mod(BigInt& rem, const BigInt& div)
{
	if (div.IsZero())
	{
		throw std::invalid_argument("Division by zero");
	}
	else if (&div == &rem)
	{
		// Aliasing...
		// Well, taking a modulo from itself is zero
		rem.SetZero();
		return;
	}

	rem.m_sign = Sign::POS; // Remainder is _always_ positive

	BigInt divisor;
	const uint64_t divBitCount = div.GetBitWidth();
	// Loop until the absolute value of divisor is smaller than remainder
	while (div.CompareWithoutSign(rem) != Comparison::GREATER)
	{
		uint64_t shift = rem.GetBitWidth() - divBitCount;
		if (div.MostSignificant() > rem.MostSignificant())
		{
			shift--;
		}
		LeftShift(divisor, div, shift);

		while (divisor.CompareWithoutSign(rem) == Comparison::GREATER)
		{
			divisor = divisor >> 1U;
			--shift;
		}

		SubstractWithoutSign(rem, divisor);
	}
}

// Function assumes that |minuendRes| > |subtrahend|
void BigInt::SubstractWithoutSign(BigInt& minuendRes, const BigInt& subtrahend)
{
	const size_t size = std::min(minuendRes.CurrentSize(), subtrahend.CurrentSize());
	#pragma loop(no_vector)
	for (size_t i = size - 1U;;)
	{
		if (_subborrow_u64(0U, minuendRes.m_vals[i], subtrahend.m_vals[i], &minuendRes.m_vals[i]))
		{
			#pragma loop(no_vector)
			for (auto ii = i + 1U; _subborrow_u64(1, minuendRes.m_vals[ii], 0U, &minuendRes.m_vals[ii]); ++ii) {}
		}
		if (i != 0U)
			--i;
		else
			break;
	}
	minuendRes.CleanPreceedingZeroes();
}

BigInt::Comparison BigInt::CompareWithSign(const BigInt& other) const
{
	if (IsPositive() == other.IsPositive())
	{
		// If both are positive compare this* > other
		// However, if both are negative, reserve the order (as bigger is smaller with negative numbers)
		return IsPositive() ? CompareWithoutSign(other) : other.CompareWithoutSign(*this);
	}

	// The sign of *this and other are different
	// If *this is positive and 'other' is negative and then *this is bigger
	// If *this is negative and 'other' is positive, then *this is smaller
	return IsPositive() ? Comparison::GREATER : Comparison::LESSER;
}

// Compares *this to 'other'
// If both are equal, function return Comparison::EQUAL
// If *this > other, function returns Comparison::GREATER
// Comparison::LESSER otherwise
BigInt::Comparison BigInt::CompareWithoutSign(const BigInt& other) const
{
	Comparison res = Comparison::EQUAL;
	if (CurrentSize() == other.CurrentSize())
	{
		// Sizes are equal
		for (size_t i = CurrentSize() - 1U;; --i)
		{
			if (m_vals[i] > other.m_vals[i])
			{
				res = Comparison::GREATER;
				break;
			}
			else if (m_vals[i] < other.m_vals[i])
			{
				res = Comparison::LESSER;
				break;
			}
			// Current elements are equal, continue to the next

			if (i == 0U)
			{
				// Values are equal
				res = Comparison::EQUAL;
				break;
			}
		}
	}
	else
	{
		// Assuming the leading zeroes have been removed,
		// it is sufficient to compare only the sizes
		res = CurrentSize() > other.CurrentSize() ? Comparison::GREATER : Comparison::LESSER;
	}
	return res;
}

void BigInt::Resize(const size_t size)
{
	static size_t maxSize = 0U;
	if (size > MAX_SIZE)
	{
		throw std::invalid_argument("Overflow detected");
	}
#ifdef _DEBUG
	const size_t oldMax = maxSize;
	maxSize = std::max(size, maxSize);
	if (maxSize > oldMax)
	{
		std::cout << "Max size of BigInt: " << maxSize << std::endl;
	}
#endif
	m_vals.m_currentSize = size;
}

BigInt::Base BigInt::MostSignificant() const
{
	Base ret = 0U;
	if (IsZero())
	{
		return ret;
	}
	else if (CurrentSize() == 1U)
	{
		unsigned long index = 0U;
		if (_BitScanReverse64(&index, m_vals[0U]))
		{
			const auto shift = int((BASE_BITS)-1U - index);
			ret = __ll_lshift(m_vals[0U], shift);
		}
	}
	else if (CurrentSize() > 1U)
	{
		unsigned long index = 0U;
		if (_BitScanReverse64(&index, m_vals[CurrentSize() - 1U]))
		{
			// Shift values left so that the highest bit of Base is MSB

			// index is a number from [0...63] and Base is 64 bit
			// -> Result cannot be negative or
			const auto shift = unsigned char(BASE_BITS - 1U - unsigned char(index));
			ret = __shiftleft128(m_vals[CurrentSize() - 2U], m_vals[CurrentSize() - 1U], shift);
		}
	}
	return ret;
}

size_t BigInt::GetLSB() const
{
	size_t ret = 0U;
	for (auto i = 0U; i < CurrentSize(); ++i)
	{
		unsigned long index = 0U;
		if (_BitScanForward64(&index, m_vals[i]))
		{
			ret = index + (BASE_BITS * i);
			break;
		}
	}
	return ret;
}

void BigInt::CopyFromSrc(const void* src,
	const size_t count,
	const size_t copyToIndex)
{
	void* dst = &m_vals[copyToIndex];
	memcpy(dst, src, count * sizeof(Base));
}
