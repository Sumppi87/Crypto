#include "pch.h"
#include "BigInt.h"
#include <type_traits>
#include <string>
#include <cstdlib>
#include <algorithm>
#include <iostream>
#include <vector>
#include <intrin.h>
#include <immintrin.h>

namespace
{
	char NumToChar(const uint8_t num)
	{
		switch (num)
		{
		case 0:
			return '0';
		case 1:
			return '1';
		case 2:
			return '2';
		case 3:
			return '3';
		case 4:
			return '4';
		case 5:
			return '5';
		case 6:
			return '6';
		case 7:
			return '7';
		case 8:
			return '8';
		case 9:
			return '9';
		case 10:
			return 'A';
		case 11:
			return 'B';
		case 12:
			return 'C';
		case 13:
			return 'D';
		case 14:
			return 'E';
		case 15:
			return 'F';
		default:
			throw std::invalid_argument("Not a valid hexadecimal");
			break;
		}
	}

	uint8_t CharToNum(const char c, bool isHex)
	{
		switch (c)
		{
		case '0':
			return 0;
		case '1':
			return 1;
		case '2':
			return 2;
		case '3':
			return 3;
		case '4':
			return 4;
		case '5':
			return 5;
		case '6':
			return 6;
		case '7':
			return 7;
		case '8':
			return 8;
		case '9':
			return 9;
		default:
			if (!isHex)
				throw std::invalid_argument("Not a valid decimal number");
			switch (c)
			{
			case 'A':
				return 10;
			case 'B':
				return 11;
			case 'C':
				return 12;
			case 'D':
				return 13;
			case 'E':
				return 14;
			case 'F':
				return 15;
			default:
				throw std::invalid_argument("Not a valid hexadecimal");
				break;
			}
		}
	}

#ifdef TEST
	inline unsigned __int64 mulhi(unsigned __int64 a, unsigned __int64 b)
	{
		uint64_t a_lo = (uint32_t)a;
		uint64_t a_hi = a >> 32;
		uint64_t b_lo = (uint32_t)b;
		uint64_t b_hi = b >> 32;

		uint64_t a_x_b_hi = a_hi * b_hi;
		uint64_t a_x_b_mid = a_hi * b_lo;
		uint64_t b_x_a_mid = b_hi * a_lo;
		uint64_t a_x_b_lo = a_lo * b_lo;

		uint64_t carry_bit = ((uint64_t)(uint32_t)a_x_b_mid +
			(uint64_t)(uint32_t)b_x_a_mid +
			(a_x_b_lo >> 32)) >> 32;

		uint64_t multhi = a_x_b_hi +
			(a_x_b_mid >> 32) + (b_x_a_mid >> 32) +
			carry_bit;
		return multhi;
	}

	unsigned __int64 _umul128(unsigned __int64 a, unsigned __int64 b, unsigned __int64* pHigh)
	{
		*pHigh = mulhi(a, b);
		return a * b;
	}

	unsigned char _addcarry_u64(unsigned char c_in, unsigned __int64 a, unsigned __int64 b, unsigned __int64 *sum_out)
	{
		const uint32_t a_lo = uint32_t(a);
		const uint32_t a_hi = uint32_t(a >> 32);
		const uint32_t b_lo = uint32_t(b);
		const uint32_t b_hi = uint32_t(b >> 32);
		const uint64_t lo = a_lo + b_lo + (c_in > 0 ? 1 : 0);
		const uint64_t hi = a_hi + b_hi;

		*sum_out = ((hi << 32) | lo);

		return (hi >> 32) > 0 ? unsigned char(1) : unsigned char(0);
	}
#endif

#if defined (USE_64BIT_VALUES)
	inline void AddResult(uint64_t* src, const uint64_t val)
	{
		if (_addcarry_u64(0, val, *src, src))
		{
			AddResult(src + 1, 1);
		}
	};

	inline void SubResult(uint64_t* src, const uint64_t val, const unsigned char carry)
	{
		if (_subborrow_u64(carry, *src, val, src))
		{
			SubResult(src + 1, 0, 1);
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
#else
	template <typename Base, typename Mul>
	union MulUtil
	{
		MulUtil(const Mul m)
			: val(m) {}

		Mul val;
		struct
		{
			Base valLower;
			Base carryOver;
		};
	};

	template <typename Base, typename Mul>
	void AddResult(std::vector<Base>& res, const MulUtil<Base, Mul> mul, const size_t index)
	{
		// First, handle carry over
		if (mul.carryOver)
		{
			AddResult(res, MulUtil<Base, Mul>(mul.carryOver), index + 1);
		}

		const MulUtil<Base, Mul> t((Mul)res[index] + (Mul)mul.valLower);
		res[index] = t.valLower;

		if (t.carryOver)
		{
			AddResult(res, MulUtil<Base, Mul>(t.carryOver), index + 1);
		}
	};
#endif
}

/*static*/
BigInt BigInt::FromRawData(const char* data, const size_t length)
{
	BigInt res;

	const auto chunks = length / sizeof(Base);
	const auto leftOver = length % sizeof(Base);
	res.Resize(chunks + (leftOver > 0 ? 1 : 0));

	size_t readChars = 0;
	for (size_t i = 0; i < res.CurrentSize(); ++i)
	{
		for (size_t charPos = 0
			; readChars < length && charPos < sizeof(Base)
			; ++charPos, ++readChars)
		{
			const auto shift = charPos * 8;
			const char c = data[readChars];
			const Base shiftedC = (Base(c) << shift);
			res.m_vals[i] |= shiftedC;
		}
	}

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
	if (length < 1)
	{
		throw std::invalid_argument("Not a valid input");
	}
	if (input[0] == '-')
	{
		// It's a negative number
		++input;
		--length;
		m_sign = Sign::NEG;
	}

	if (length > 2 && input[0] == '0' && input[1] == 'x')
	{
		input += 2;
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
	if (length < 1)
	{
		throw std::invalid_argument("Not a valid decimal");
	}

	BigInt ten(10);

	for (size_t i = 0; i < length; ++i)
	{
		BigInt digit;
		digit.m_vals[size_t(0)] = CharToNum(input[i], false);
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
	if (length < 1)
	{
		throw std::invalid_argument("Not a valid hexadecimal");
	}

	std::lldiv_t div = std::lldiv(int64_t(length), int64_t((sizeof(Base) * 2)));
	const size_t neededSize = div.rem == 0 ? div.quot : div.quot + 1;
	Resize(neededSize);

	for (size_t i = length - 1;; --i)
	{
		const std::div_t d = std::div(int((length - 1) - i), int(sizeof(Base) * 2));
		const size_t index = d.quot;
		const size_t shift = d.rem * 4;
		const Base val = CharToNum(hex[i], true);
		const Base shifted = (val << shift);
		m_vals[index] += shifted;
		if (i == 0)
		{
			break;
		}
	}
}

BigInt::BigInt()
	: m_sign(Sign::POS)
	, m_currentSize(1)
	, m_vals{}
{
	m_vals[0] = 0;
}

BigInt::BigInt(const BigInt& other)
	: m_sign(other.m_sign)
	, m_currentSize(other.m_currentSize)
	, m_vals{}
{
	CopyFromSrc(other.m_vals, other.CurrentSize(), 0);
}

BigInt::BigInt(const BigInt&& move)
	: m_sign(move.m_sign)
	, m_currentSize(move.m_currentSize)
	, m_vals{}
{
	CopyFromSrc(move.m_vals, m_currentSize, 0);
}

BigInt& BigInt::operator=(const BigInt& other)
{
	m_sign = other.m_sign;

	// Clear any old values before assigment if *this is larger
	if (other.m_currentSize < m_currentSize)
		memset(m_vals, 0, m_currentSize * sizeof(Base));

	m_currentSize = other.m_currentSize;
	CopyFromSrc(other.m_vals, m_currentSize, 0);
	return *this;
}

BigInt& BigInt::operator=(const BigInt&& other)
{
	m_sign = other.m_sign;

	// Clear any old values before assigment if *this is larger
	if (other.m_currentSize < m_currentSize)
		memset(m_vals, 0, m_currentSize * sizeof(Base));

	m_currentSize = other.m_currentSize;
	CopyFromSrc(other.m_vals, m_currentSize, 0);
	return *this;
}

BigInt::BigInt(const Base* data, const size_t currentSize)
	: m_sign(Sign::POS)
	, m_currentSize(currentSize)
	, m_vals{}
{
	CopyFromSrc(data, currentSize, 0);
}

BigInt::BigInt(const uint8_t val)
	: m_sign(Sign::POS)
	, m_currentSize(0)
	, m_vals{}
{
	FromNum(val, sizeof(uint8_t));
}

BigInt::BigInt(const uint16_t val)
	: m_sign(Sign::POS)
	, m_currentSize(0)
	, m_vals{}
{
	FromNum(val, sizeof(uint16_t));
}

BigInt::BigInt(const uint32_t val)
	: m_sign(Sign::POS)
	, m_currentSize(0)
	, m_vals{}
{
	FromNum(val, sizeof(uint32_t));
}

BigInt::BigInt(const uint64_t val)
	: m_sign(Sign::POS)
	, m_currentSize(0)
	, m_vals{}
{
	FromNum(val, sizeof(uint64_t));
}

BigInt::BigInt(const int val)
	: m_sign(val < 0 ? Sign::NEG : Sign::POS)
	, m_currentSize(0)
	, m_vals{}
{
	FromNum(val < 0 ? uint32_t(-val) : (uint32_t)val, sizeof(uint32_t));
}

BigInt::BigInt(const int64_t val)
	: m_sign(val < 0 ? Sign::NEG : Sign::POS)
	, m_vals{}
	, m_currentSize(0)
{
	FromNum(val < 0 ? uint64_t(-val) : (uint64_t)val, sizeof(uint64_t));
}

BigInt::BigInt(const char* input)
	: m_sign(Sign::POS)
	, m_vals{}
	, m_currentSize(0)
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
			return BigInt(0);
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
	uint64_t base = 0;
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
	uint64_t base = 0;
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

		for (size_t i = 0; i < CurrentSize(); ++i)
		{
			for (size_t ii = 0; ii < other.CurrentSize(); ++ii)
			{
#if defined(USE_64BIT_VALUES)
				Base carry = 0;
				const Base mul = _umul128(m_vals[i], other.m_vals[ii], &carry);
				AddResult(&res.m_vals[i + ii], mul);
				if (carry)
					AddResult(&res.m_vals[i + ii + 1], carry);
#else

				const Mul val1 = multiplier[i];
				const Mul val2 = multiplied[ii];
				if (val1 == 0 || val2 == 0)
				{
					continue;
			}
				MulUtil<Base, Mul> mul(val1 * val2);
				AddResult(res.m_vals, mul, i + ii);
#endif
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
	BigInt copy = BigInt(1);
	copy.m_sign = (IsPositive() || !exp.IsOdd()) ? Sign::POS : Sign::NEG;
	uint64_t shift = 0;

	while (!e.IsZero())
	{
		if (e.IsOdd())
		{
			copy = copy * base;
			copy = copy % mod;
			//*this *= base;
			//*this %= mod;
		}

		RightShift(e, exp, ++shift);
		base = base * base;
		base = base % mod;
		//e >>= 1;
		//base *= base;
		//base %= mod;
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
	BigInt copy = BigInt(1);
	copy.m_sign = (IsPositive() || !exp.IsOdd()) ? Sign::POS : Sign::NEG;

	while (!e.IsZero())
	{
		if (e.IsOdd())
		{
			copy = copy * base;
		}

		e = e >> 1;
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
	else if (shift == 0)
	{
		res = target;
		return;
	}

	// Inherits the sign from target
	res.m_sign = target.m_sign;
	memset(res.m_vals, 0, sizeof(Base) * res.m_currentSize);

	const uint64_t quot = (shift / (sizeof(Base) * 8));
	const unsigned char rem = (shift % (sizeof(Base) * 8));

	if ((quot + target.CurrentSize() + (rem > 0 ? 1 : 0)) >= MAX_SIZE)
	{
		throw std::invalid_argument("Overflow detected");
	}
	else if (rem == 0)
	{
		// Add elements by the given quotient
		res.Resize(quot + target.CurrentSize());

		// Simpler case, just add elements after added zeroes
		res.CopyFromSrc(&target.m_vals[0], target.CurrentSize(), quot);
		res.CleanPreceedingZeroes();
	}
	else if (rem % 8 == 0)
	{
		const auto bytesToShift = rem / 8;
		const auto currSize = target.CurrentSize();
		res.Resize(quot + currSize + 1);

		const void* src = &target.m_vals[0];
		void* dst = GetShiftedPtr(&res.m_vals[quot], bytesToShift);
		auto count = currSize * sizeof(Base);
		memcpy(dst, src, count);
		res.CleanPreceedingZeroes();
	}
	else
	{
		const auto currSize = target.CurrentSize();
		res.Resize(quot + currSize + 1);

		// As a optimization, do the "special cases" outside the for-loop
		// It has a measurable impact on performance to _not_ have any if-conditions in the loop
		res.m_vals[size_t(quot)] = __ll_lshift(target.m_vals[0], rem);
		res.m_vals[currSize + size_t(quot)] = __shiftleft128(target.m_vals[currSize - 1], 0, rem);

		for (size_t i = 1; i < currSize; ++i)
		{
			res.m_vals[i + size_t(quot)] = __shiftleft128(target.m_vals[i - 1], target.m_vals[i], rem);
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
	else if (shift == 0)
	{
		res = target;
		return;
	}
	else if (shift >= (target.CurrentSize() * sizeof(Base) * 8))
	{
		// A quick cursoly check if shift definately bigger than 'target'
		// More detailed check is done by checking the actual bit-count if this check is passed
		res = BigInt();
		return;
	}

	// Inherits the sign from 'target'
	res.m_sign = target.m_sign;

	const auto quot = (shift / (sizeof(Base) * 8));
	const unsigned char rem = (shift % (sizeof(Base) * 8));

	const uint64_t width = target.GetBitWidth();
	if (shift >= width)
	{
		res = BigInt();
		return;
	}
	else if (rem == 0)
	{
		// Simpler case, just drop elements from the start

		res.Resize(target.CurrentSize() - quot);
		res.CopyFromSrc(&target.m_vals[quot], target.CurrentSize() - quot, 0);
		res.CleanPreceedingZeroes();
	}
	else if (rem % 8 == 0)
	{
		const auto bytesToShift = rem / 8;
		const auto currSize = target.CurrentSize();
		res.Resize(currSize - quot);

		const void* src = GetShiftedPtr(&target.m_vals[quot], bytesToShift);
		void* dst = &res.m_vals[0];
		auto count = (currSize * sizeof(Base)) - bytesToShift;
		memcpy(dst, src, count);
		res.CleanPreceedingZeroes();
	}
	else
	{
		res.Resize(target.CurrentSize() - quot);

		const auto maxIndex = target.CurrentSize();
		for (size_t i = size_t(quot); i < maxIndex; ++i)
		{
			res.m_vals[i - size_t(quot)] = __shiftright128(target.m_vals[i], target.m_vals[i + 1], rem);
		}

		// Shift amount has already been checked -> Cannot overindex
		res.m_vals[0] |= __ull_rshift(target.m_vals[quot], rem);
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
	for (size_t i = CurrentSize() - 1;; --i)
	{
		for (int nibbleNro = (sizeof(Base) * 2) - 1; nibbleNro >= 0; --nibbleNro)
		{
			const auto mask = (Base(0xF) << (nibbleNro * 4));
			const auto nibble = Base(m_vals[i] & mask) >> (nibbleNro * 4);
			if (!nonZeroAdded && nibble == 0)
			{
				continue;
			}
			nonZeroAdded = true;
			ret += NumToChar(char(nibble));
		}
		if (i == 0)
			break;
	}
	if (!nonZeroAdded)
	{
		ret += NumToChar(0);
	}
	return ret;
}

std::string BigInt::ToRawData() const
{
	std::string ret;

	for (size_t i = 0; i < CurrentSize(); ++i)
	{
		for (size_t charPos = 0; charPos < sizeof(Base); ++charPos)
		{
			const Base mask = (Base(0xFF) << (charPos * 8));
			const auto shift = (charPos * 8);
			Base c = Base(m_vals[i] & mask);
			c = (c >> shift);

			if (i == (CurrentSize() - 1)
				&& c == 0)
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
	if (CurrentSize() == 0
		|| (CurrentSize() == 1
			&& m_vals[0] == 0))
	{
		return true;
	}
	return false;
}

bool BigInt::IsOne() const
{
	return (CurrentSize() == 1 && m_vals[0] == 1);
}

bool BigInt::IsOdd() const
{
	if (IsZero())
	{
		return false;
	}
	return (m_vals[0] & 1) == 1;
}

bool BigInt::IsPositive() const
{
	return m_sign == Sign::POS;
}

BigInt BigInt::GreatestCommonDivisor(const BigInt& other, uint64_t& iters) const
{
	BigInt copy(*this);
	BigInt div(other);
	while (1)
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
	BigInt old_s(1);
	BigInt t(1);
	BigInt old_t(0);
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
			divisor = divisor >> 1;
			--shift;
		}

		if (pQuot)
		{
			pQuot->SetBit(shift);
		}

		SubstractWithoutSign(rem, divisor);
	}
}

void BigInt::SetBit(const uint64_t bitNo)
{
	const uint64_t elementNo = (bitNo / (sizeof(Base) * 8));
	const size_t bitNoInElement = (bitNo % (sizeof(Base) * 8));

	if (elementNo >= CurrentSize())
	{
		// Size needs to be increased
		// elementNo is an index starting from 0 -> add 1
		Resize(elementNo + 1);
	}

	m_vals[size_t(elementNo)] |= (Base(1) << bitNoInElement);
}

uint64_t BigInt::GetBitWidth() const
{
	if (!IsZero())
	{
		uint64_t count = (CurrentSize() - 1) * (sizeof(Base) * 8);
		unsigned long index = 0;
		if (_BitScanReverse64(&index, m_vals[CurrentSize() - 1]))
		{
			count += (1 + index);
		}
		return count;
	}
	return 0;
}

bool BigInt::IsBase2(uint64_t& base) const
{
	uint64_t t = 0;
	if (IsZero())
	{
		return false;
	}

	bool bitFound = false;
	for (size_t i = 0; i < CurrentSize(); ++i)
	{
		const Base v = m_vals[i];
		unsigned long f = 0;
		unsigned long r = 0;
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
			t += sizeof(Base) * 8;
		}
	}
	base = bitFound ? t : 0;
	return bitFound;
}

void BigInt::CleanPreceedingZeroes()
{
	for (auto i = CurrentSize() - 1; i > 0; --i)
	{
		if (m_vals[i] == 0)
		{
			m_currentSize--;
		}
		else
		{
			break;
		}
	}
}

void BigInt::FromNum(const uint64_t val, const uint8_t size)
{
	const size_t chunks = size / sizeof(Base);
	Resize(chunks == 0 ? 1 : chunks);
	for (size_t i = 0; i < CurrentSize(); ++i)
	{
		const auto shift = sizeof(Base) * 8 * i;
		m_vals[i] = Base(val >> shift);
	}
	CleanPreceedingZeroes();
}

BigInt BigInt::SumWithoutSign(const BigInt& other) const
{
	BigInt copy;
	const auto s = std::max(other.m_currentSize, m_currentSize) + 1;

	copy.Resize(s);
	const size_t size = copy.CurrentSize();
	const size_t size2 = other.CurrentSize();

	for (size_t i = 0; i < size; ++i)
	{
#if defined(USE_64BIT_VALUES)
		const Base val1 = i < size ? m_vals[i] : 0;
		const Base val2 = i < size2 ? other.m_vals[i] : 0;

		Base sum = 0;
		if (_addcarry_u64(0, val1, val2, &sum))
			AddResult(&copy.m_vals[i + 1], 1);
		AddResult(&copy.m_vals[i], sum);

#else
		const Mul val1 = i < size ? m_vals[i] : 0;
		const Mul val2 = i < size2 ? other.m_vals[i] : 0;
		MulUtil<Base, Mul> sum(val1 + val2);
		AddResult(copy.m_vals, sum, i);
#endif
	}

	copy.CleanPreceedingZeroes();
	return copy;
}


BigInt BigInt::SubstractWithoutSign(const BigInt& other) const
{
	BigInt copy(*this);
	const size_t size = std::min(CurrentSize(), other.CurrentSize());
	for (size_t i = 0; i < size; ++i)
	{
		const Base val = other.m_vals[i];
		SubResult(&copy.m_vals[i], val, 0);
	}
	copy.CleanPreceedingZeroes();
	return copy;
}

void BigInt::SubstractWithoutSign(BigInt& minuendRes, const BigInt& subtrahend)
{
	const size_t size = std::max(minuendRes.CurrentSize(), subtrahend.CurrentSize());
	for (size_t i = size - 1;;)
	{
		const Base val = subtrahend.m_vals[i];
		SubResult(&minuendRes.m_vals[i], val, 0);
		if (i != 0)
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
		for (size_t i = CurrentSize() - 1;; --i)
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

			if (i == 0)
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
	static size_t maxSize = 0;
	if (size >= MAX_SIZE)
	{
		throw std::invalid_argument("Overflow detected");
	}
	const size_t oldMax = maxSize;
	maxSize = std::max(size, maxSize);
	if (maxSize > oldMax)
	{
		std::cout << "Max size of BigInt: " << maxSize << std::endl;
	}
	m_currentSize = size;
}

BigInt::Base BigInt::MostSignificant() const
{
	Base ret = 0;
	if (IsZero())
	{
		return ret;
	}
	else if (m_currentSize == 1)
	{
		unsigned long index = 0;
		if (_BitScanReverse64(&index, m_vals[0]))
		{
			const auto shift = int((sizeof(Base) * 8) - 1 - index);
			ret = __ll_lshift(m_vals[0], shift);
		}
	}
	else
	{
		unsigned long index = 0;
		if (_BitScanReverse64(&index, m_vals[m_currentSize - 1]))
		{
			const auto shift = int((sizeof(Base) * 8) - 1 - index);
			ret = __shiftleft128(m_vals[m_currentSize - 2], m_vals[m_currentSize - 1], shift);
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
