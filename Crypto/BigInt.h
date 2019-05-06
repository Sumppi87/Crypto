#pragma once
#include <string>
#include <atomic>

#define MAX_SIZE 64

class CryptoUtils;

class BigInt
{
public:

#if defined(_M_X64)
	typedef uint64_t Base;
#endif

	static BigInt FromRawData(const char* data, const size_t length);
	static BigInt FromString(const char* input);

	BigInt();

	BigInt(const uint8_t val);
	BigInt(const uint16_t val);
	BigInt(const uint32_t val);
	BigInt(const int val);

	BigInt(const uint64_t val);
	BigInt(const int64_t val);
	BigInt(const char* input);

	BigInt operator+(const BigInt& other) const;
	BigInt operator-(const BigInt& other) const;
	BigInt operator%(const BigInt& other) const;
	BigInt operator/(const BigInt& other) const;
	BigInt operator*(const BigInt& other) const;

	inline BigInt PowMod(const BigInt& exp, const BigInt& mod) const;

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

	std::string ToDec() const;

	std::string ToRawData() const;

	inline bool IsZero() const;

	bool IsOne() const;

	inline bool IsOdd() const;

	inline bool IsPositive() const;

	BigInt GreatestCommonDivisor(const BigInt& other, uint64_t& iters) const;

	BigInt ModuloMultiplicativeInverse(const BigInt& M) const;

	void ExtendedEuclididan(const BigInt& b, BigInt& gcd, BigInt& x, BigInt& y) const;

	bool IsPrimeNumber() const;

	void SetBit(const uint64_t bitNo);

	inline uint64_t GetBitWidth() const;
	uint64_t GetByteWidth() const;

	bool IsBase2(uint64_t& base) const;

	void SetZero();

	inline size_t CurrentSize() const;

private:
	void IsPrimeNumberPriv(std::atomic<uint8_t>* iters, bool* pStop) const;

	void Div(const BigInt& div, BigInt& rem, BigInt* pQuot = nullptr) const;

	inline void CleanPreceedingZeroes();

	void FromNum(const uint64_t val, const uint8_t size);

	BigInt SumWithoutSign(const BigInt& other) const;

	BigInt SubstractWithoutSign(const BigInt& other) const;

	// In-place helper functions
	static inline void Mod(BigInt& rem, const BigInt& div);
	static inline void SubstractWithoutSign(BigInt& minuendRes, const BigInt& subtrahend);
	static inline void LeftShift(BigInt& res, const BigInt& target, const uint64_t shift);
	static inline void RightShift(BigInt& res, const BigInt& target, const uint64_t shift);

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
	inline Comparison CompareWithoutSign(const BigInt& other) const;

	inline void Resize(const size_t size);

	// Returns a value starting from MSB (of the whole BigInt)
	inline Base MostSignificant() const;

	// Gets the bitnumber of least significant bit
	size_t GetLSB() const;

	inline void CopyFromSrc(const void* src,
		const size_t count,
		const size_t copyToIndex);

	BigInt& ParseStrInput(const char* input);
	void FromBase10(const char* input);
	void FromBase16(const char* hex);

	BigInt(const Base* data, const size_t currentSize);

private:
	enum class Sign : size_t
	{
		POS,
		NEG
	};

	Sign m_sign;

	struct ValueContainer
	{
		ValueContainer();

		void SetZero();

		inline void CleanPreceedingZeroes();

		inline Base& operator[](const size_t index);
		inline const Base& operator[](const size_t index) const;

		inline operator void*();
		inline operator const void*() const;

		operator char*();
		operator const char*() const;

		inline operator uint64_t*();
		inline operator const uint64_t*() const;

		Base m_vals[MAX_SIZE];
		size_t m_currentSize;
	};

	ValueContainer m_vals;
	friend class CryptoUtils;
};
