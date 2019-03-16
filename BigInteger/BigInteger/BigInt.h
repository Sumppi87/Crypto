#pragma once
#include <vector>
#include <string>

#define USE_64BIT_IF_POSSIBLE
//#define TEST

#define MAX_SIZE 64

class BigInt
{
public:

#if (defined(_M_X64) && defined(USE_64BIT_IF_POSSIBLE)) or defined(TEST)
	typedef uint64_t Base;
#define USE_64BIT_VALUES
#else
	typedef uint32_t Base;
	typedef uint64_t Mul;
#endif

	static BigInt FromRawData(const char* data, const size_t length);
	static BigInt FromBase10(const char* input);
	static BigInt FromBase16(const char* hex);

	BigInt();

	BigInt(const BigInt& other);
	BigInt(const uint8_t val);
	BigInt(const uint16_t val);
	BigInt(const uint32_t val);
	BigInt(const int val);

	BigInt(const uint64_t val);
	BigInt(const int64_t val);
	BigInt(const char* input);

	/*struct DivRes
	{
		BigInt quotient;
		BigInt remainder;
	};

	DivRes Div(const BigInt& div) const;
	*/

	BigInt operator+(const BigInt& other) const;
	BigInt operator-(const BigInt& other) const;
	BigInt operator%(const BigInt& other) const;
	BigInt operator/(const BigInt& other) const;
	BigInt operator*(const BigInt& other) const;

	BigInt PowMod(const BigInt& exp, const BigInt& mod) const;

	BigInt Pow(const BigInt& exp) const;

	BigInt operator<<(const uint64_t shift) const;

	BigInt operator>>(const uint64_t shift) const;

	bool operator>(const BigInt& other) const;

	bool operator>=(const BigInt& other) const;

	bool operator<=(const BigInt& other) const;

	bool operator<(const BigInt& other) const;

	bool operator!=(const BigInt& other) const;

	bool operator==(const BigInt& other) const;

	std::string ToHex() const;

	std::string ToRawData() const;

	bool IsZero() const;

	bool IsOdd() const;

	bool IsPositive() const;

	BigInt GreatestCommonDivisor(const BigInt& other, uint64_t& iters) const;

	BigInt ModuloMultiplicativeInverse(const BigInt& M) const;;

	void ExtendedEuclididan(const BigInt& b, BigInt& gcd, BigInt& x, BigInt& y) const;

	void SetBit(const uint64_t bitNo);

	uint64_t GetBitWidth() const;

	bool IsBase2(uint64_t& base) const;

private:
	void Div(const BigInt& div, BigInt& rem, BigInt* pQuot = nullptr) const;

	void CleanPreceedingZeroes();

	void FromNum(const uint64_t val, const uint8_t size);

	BigInt SumWithoutSign(const BigInt& other) const;

	BigInt SubstractWithoutSign(const BigInt& other) const;

	enum class Comparison
	{
		LESSER,
		EQUAL,
		GREATER
	};

	Comparison CompareWithSign(const BigInt& other) const;

	// Compares *this to 'other'
	// If both are equal, function return Comparison::EQUAL
	// If *this > other, function returns Comparison::GREATER
	// Comparison::LESSER otherwise
	Comparison CompareWithoutSign(const BigInt& other) const;

	void Resize(const size_t size);

	inline size_t CurrentSize() const
	{
		return m_currentSize;
	}

	void CopyFromSrc(const void* src,
		const size_t count,
		const size_t copyToIndex);

	enum class ShiftDirection
	{
		RIGHT,
		LEFT
	};

	const void* GetLeftShiftedPtr(const size_t fromIndex, const unsigned char shift) const;
	const void* GetRightShiftedPtr(const size_t fromIndex, const unsigned char shift) const;

private:
	//std::vector<Base> m_vals;
	Base m_vals[MAX_SIZE];
	size_t m_currentSize;

	enum Sign
	{
		POS = 1,
		NEG = -1
	};

	Sign m_sign;
};