#pragma once
#include <type_traits>
#include <vector>
#include <string>
#include <cstdlib>
#include <algorithm>
#include <bitset>

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
}

template <typename Base, typename Mul>
class BigInt
{
	static_assert(sizeof(Base) * 2 == sizeof(Mul), "Base must be twice the size of Mul");
	static_assert(std::is_unsigned<Base>::value, "Base must be unsigned int");
	static_assert(std::is_unsigned<Mul>::value, "Base must be unsigned int");
public:

	static BigInt FromBase10(const char* input)
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
		BigInt res;

		for (size_t i = 0; i < length; ++i)
		{
			BigInt digit;
			digit.m_vals[size_t(0)] = CharToNum(input[i], false);
			res = res * ten;
			res = res + digit;
		}
		res.CleanPreceedingZeroes();

		return res;
	}

	static BigInt FromBase16(const char* hex)
	{
		if (hex == nullptr)
		{
			throw std::invalid_argument("Not a valid hexadecimal");
		}
		auto length = strlen(hex);
		if (length < 3)
		{
			throw std::invalid_argument("Not a valid hexadecimal");
		}
		if (hex[0] != '0' && hex[1] != 'x')
		{
			throw std::invalid_argument("Not a valid hexadecimal");
		}

		const size_t ignoreFrom = [hex, length]()
		{
			size_t index = 2;
			for (size_t i = index; i < length; ++i)
			{
				if (hex[i] == '0')
				{
					++index;
				}
				else
				{
					break;
				}
			}
			return index;
		}();

		BigInt res;

		std::div_t div = std::div(int(length - ignoreFrom), int((sizeof(Base) * 2)));
		const size_t neededSize = div.rem == 0 ? div.quot : div.quot + 1;
		res.m_vals.resize(neededSize, 0);

		for (size_t i = length - 1; i >= ignoreFrom; --i)
		{
			const std::div_t d = std::div(int((length - 1) - i), int(sizeof(Base) * 2));
			const size_t index = d.quot;
			const size_t shift = d.rem * 4;
			auto val = CharToNum(hex[i], true);
			const Base shifted = (val << shift);
			res.m_vals[index] += shifted;
			if (i == 0)
			{
				break;
			}
		}
		res.CleanPreceedingZeroes();

		return res;
	}

	BigInt()
	{
		m_vals.push_back(0);
	}

	BigInt(const BigInt& other)
		: m_vals(other.m_vals)
	{

	}

	BigInt(const uint8_t val)
	{
		FromNum(val);
	}

	BigInt(const uint16_t val)
	{
		FromNum(val);
	}

	BigInt(const uint32_t val)
	{
		FromNum(val);
	}

	BigInt(const uint64_t val)
	{
		FromNum(val);
	}

	BigInt(const int val)
	{
		if (val < 0)
		{
			throw std::invalid_argument("Initializing with a negative number!");
		}
		FromNum((uint32_t)val);
	}

	BigInt(const char* input)
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
		if (length > 3 && input[0] == '0' && input[1] == 'x')
		{
			*this = FromBase16(input);
		}
		else
		{
			*this = FromBase10(input);
		}
	}

	struct DivRes
	{
		BigInt quotient;
		BigInt remainder;
	};

	DivRes Div(const BigInt& div)
	{
		DivRes res;
		Div(div, res.remainder, &res.quotient);
		return res;
	}

	BigInt operator+(const BigInt& other) const
	{
		if (!other.IsZero())
		{
			BigInt copy;
			const auto s = std::max(m_vals.size(), other.m_vals.size()) + 1;
			copy.m_vals.resize(s, 0);
			const size_t size = m_vals.size();
			const size_t size2 = other.m_vals.size();

			for (size_t i = 0; i < size || i < size2; ++i)
			{
				const Mul val1 = i < size ? m_vals[i] : 0;
				const Mul val2 = i < size2 ? other.m_vals[i] : 0;
				MulUtil<Base, Mul> sum(val1 + val2);
				AddResult(copy.m_vals, sum, i);
			}

			copy.CleanPreceedingZeroes();

			return copy;
		}
		return *this;
	}

	BigInt operator-(const BigInt& other) const
	{
		if (other.IsZero())
		{
			return *this;
		}
		else if (other > *this)
		{
			throw std::logic_error("Decrement would overflow");
		}

		BigInt copy;
		copy.m_vals.resize(m_vals.size(), 0);
		const size_t size = m_vals.size();
		const size_t size2 = other.m_vals.size();

		for (size_t i = 0; i < m_vals.size(); ++i)
		{
			const Base val1 = ~Base(i < size ? m_vals[i] : 0);
			const Base val2 = Base(i < size2 ? other.m_vals[i] : 0);
			MulUtil<Base, Mul> sum(Mul(val1) + Mul(val2));
			AddResult(copy.m_vals, sum, i);
			copy.m_vals[i] = ~copy.m_vals[i];
		}
		copy.CleanPreceedingZeroes();

		return copy;
	}

	BigInt operator%(const BigInt& other) const
	{
		if (other.IsZero())
		{
			throw std::invalid_argument("Division by zero");
		}
		else if (*this < other)
		{
			return *this;
		}

		BigInt remainder;
		Div(other, remainder, nullptr);
		return remainder;
	}

	BigInt operator/(const BigInt& other) const
	{
		uint64_t base = 0;
		if (other.IsZero())
		{
			throw std::invalid_argument("Division by zero");
		}
		else if (other.IsBase2(base))
		{
			// If the divisor is base-2, a simple shift will do
			return *this >> base;
		}

		BigInt remainder;
		BigInt quot;
		Div(other, remainder, &quot);
		return quot;
	}

	BigInt operator*(const BigInt& other) const
	{
		if (IsZero() || other.IsZero())
		{
			return BigInt();
		}
		else
		{
			const auto s = m_vals.size() + other.m_vals.size();
			BigInt copy;
			copy.m_vals.resize(s, 0);

			BigInt test = (copy >> 1);
			const std::vector<Base>& multiplier = m_vals.size() <= other.m_vals.size() ? m_vals : other.m_vals;
			const std::vector<Base>& multiplied = m_vals.size() > other.m_vals.size() ? m_vals : other.m_vals;

			for (size_t i = 0; i < multiplier.size(); ++i)
			{
				for (size_t ii = 0; ii < multiplied.size(); ++ii)
				{
					const Mul val1 = multiplier[i];
					const Mul val2 = multiplied[ii];
					if (val1 == 0 || val2 == 0)
					{
						continue;
					}
					MulUtil<Base, Mul> mul(val1 * val2);
					AddResult(copy.m_vals, mul, i + ii);
				}
			}

			copy.CleanPreceedingZeroes();

			return copy;
		}
	}

	BigInt PowMod(const BigInt& exp, const BigInt& mod) const
	{
		BigInt e = exp;
		BigInt base = *this;
		BigInt copy = BigInt(1);

		while (!e.IsZero())
		{
			if (e.IsOdd())
			{
				copy = copy * base;
				copy = copy % mod;
				//*this *= base;
				//*this %= mod;
			}

			e = e >> 1;
			base = base * base;
			base = base % mod;
			//e >>= 1;
			//base *= base;
			//base %= mod;
		}
		return copy;
	}

	BigInt operator<<(const uint64_t shift) const
	{
		if (IsZero())
		{
			return BigInt();
		}
		else if (shift == 0)
		{
			return *this;
		}

		BigInt copy;

		const uint64_t quot = (shift / (sizeof(Base) * 8));
		const auto rem = (shift % (sizeof(Base) * 8));

		if ((quot + m_vals.size() + (rem > 0 ? 1 : 0)) >= m_vals.max_size())
		{
			throw std::invalid_argument("Overflow detected");
		}
		else if (rem == 0)
		{
			// Add elements by the given quotient
			copy.m_vals.resize(size_t(quot), 0);

			// Simpler case, just add elements after added zeroes
			copy.m_vals.insert(copy.m_vals.begin() + size_t(quot), m_vals.begin(), m_vals.end());
		}
		else
		{
			// Size of m_vals is incremented by quotient and possibly by one due to remainder
			// -> Shifting last element can go into the +1 element
			copy.m_vals.resize(m_vals.size() + size_t(quot) + 1, 0);

			for (size_t i = 0; i <= m_vals.size(); ++i)
			{
				Base valLower = (i > 0) ? m_vals[i - 1] : 0;
				valLower = valLower >> ((sizeof(Base) * 8) - rem);

				Base val = (i < m_vals.size()) ? m_vals[i] : 0;
				val = val << rem;
				copy.m_vals[i + size_t(quot)] = val | valLower;
			}
			copy.CleanPreceedingZeroes();
		}
		return copy;
	}

	BigInt operator>>(const uint64_t shift) const
	{
		if (IsZero())
		{
			return BigInt();
		}
		else if (shift == 0)
		{
			return *this;
		}

		BigInt copy;

		const auto quot = (shift / (sizeof(Base) * 8));
		const auto rem = (shift % (sizeof(Base) * 8));

		const uint64_t width = GetBitWidth();
		if (shift >= width)
		{
			return copy;
		}
		else if (rem == 0)
		{
			// Simpler case, just drop elements from the start
			copy.m_vals = std::vector<Base>(m_vals.begin() + size_t(quot), m_vals.end());
		}
		else
		{
			// More complicated as the shift crosses element (in m_vals) boundaries

			copy.m_vals.resize(m_vals.size() - size_t(quot), 0);

			for (size_t i = size_t(quot); i < m_vals.size(); ++i)
			{
				const Base val = (m_vals[i] >> uint32_t(rem));
				Base upperVal = ((i + 1) < m_vals.size()) ? m_vals[i + 1] : 0;
				upperVal = upperVal << ((sizeof(Base) * 8) - rem);
				copy.m_vals[i - size_t(quot)] = val | upperVal;
			}
			copy.CleanPreceedingZeroes();
		}
		return copy;
	}

	bool operator>(const BigInt& other) const
	{
		bool bigger = false;
		if (m_vals.size() == other.m_vals.size())
		{
			for (size_t i = m_vals.size() - 1;; --i)
			{
				if (m_vals[i] > other.m_vals[i])
				{
					bigger = true;
					break;
				}
				else if (m_vals[i] < other.m_vals[i])
				{
					break;
				}
				// Current elements are equal, continue to the next

				if (i == 0)
				{
					// Last element, still equal -> not bigger
					bigger = false;
					break;
				}
			}
		}
		else
		{
			bigger = m_vals.size() > other.m_vals.size();
		}
		return bigger;
	}

	bool operator>=(const BigInt& other) const
	{
		bool greaterOrEqual = true;
		if (m_vals.size() == other.m_vals.size())
		{
			for (size_t i = m_vals.size() - 1;; --i)
			{
				if (m_vals[i] > other.m_vals[i])
				{
					greaterOrEqual = true;
					break;
				}
				else if (m_vals[i] < other.m_vals[i])
				{
					greaterOrEqual = false;
					break;
				}
				// Current elements are equal, continue to the next

				if (i == 0)
				{
					greaterOrEqual = true;
					break;
				}
			}
		}
		else
		{
			greaterOrEqual = m_vals.size() > other.m_vals.size();
		}
		return greaterOrEqual;
	}

	bool operator<=(const BigInt& other) const
	{
		return !(*this > other);
	}

	bool operator<(const BigInt& other) const
	{
		return !(*this >= other);
	}

	bool operator!=(const BigInt& other) const
	{
		return !(*this == other);
	}

	bool operator==(const BigInt& other) const
	{
		bool equal = true;
		if (m_vals.size() == other.m_vals.size())
		{
			for (size_t i = m_vals.size() - 1; i <= 0; --i)
			{
				if (!(m_vals[i] == other.m_vals[i]))
				{
					break;
				}

				if (i == 0)
				{
					break;
				}
			}
		}
		else
		{
			equal = false;
		}
		return equal;
	}

	std::string toHex() const
	{
		if (IsZero())
		{
			return "0x0";
		}

		std::string ret;
		ret.append("0x");
		bool nonZeroAdded = false;
		for (int i = m_vals.size() - 1; i >= 0; --i)
		{
			for (int nibbleNro = (sizeof(Base) * 2) - 1; nibbleNro >= 0; --nibbleNro)
			{
				const Base mask = (0xF << (nibbleNro * 4));
				const int nibble = (m_vals[i] & mask) >> (nibbleNro * 4);
				if (!nonZeroAdded && nibble == 0)
				{
					continue;
				}
				nonZeroAdded = true;
				ret += NumToChar(char(nibble));
			}
		}
		if (!nonZeroAdded)
		{
			ret += NumToChar(0);
		}
		return ret;
	}

	bool IsZero() const
	{
		if (m_vals.size() == 0
			|| (m_vals.size() == 1
				&& m_vals[0] == 0))
		{
			return true;
		}
		return false;
	}

	bool IsOdd() const
	{
		if (IsZero())
		{
			return false;
		}
		return (m_vals[0] & 1) == 1;
	}

	BigInt GreatestCommonDivisor(const BigInt& other, uint64_t& iters) const
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

	BigInt ModuloMultiplicativeInverse(const BigInt& mod)
	{
		// Assumes that M is a prime number
		// Returns multiplicative modulo inverse of *this under M
		return PowMod(mod - 2, mod);
	}
private:
	void Div(const BigInt& div, BigInt& rem, BigInt* pQuot = nullptr) const
	{
		if (IsZero())
		{
			throw std::invalid_argument("Division by zero");
		}

		rem = BigInt(*this);

		while (rem >= div)
		{
			uint64_t shift = rem.GetBitWidth() - div.GetBitWidth();
			BigInt divisor = div << shift;
			while (divisor > rem)
			{
				divisor = divisor >> 1;
				--shift;
			}
			if ((divisor << 1) < rem)
			{
				divisor = divisor << 1;
			}

			if (pQuot)
			{
				pQuot->SetBit(shift);
			}
			rem = rem - divisor;
		}
	}

	void SetBit(const uint64_t bitNo)
	{
		const uint64_t elementNo = (bitNo / (sizeof(Base) * 8));
		const size_t bitNoInElement = (bitNo % (sizeof(Base) * 8));

		if (elementNo >= m_vals.size())
		{
			// Size needs to be increased
			if (elementNo >= m_vals.max_size())
			{
				throw std::invalid_argument("Overflow detected");
			}

			// elementNo is an index starting from 0 -> add 1
			m_vals.resize(size_t(elementNo + 1), 0);
		}

		m_vals[size_t(elementNo)] |= (1 << bitNoInElement);
	}

	uint64_t GetBitWidth() const
	{
		if (!IsZero())
		{
			uint64_t count = (m_vals.size() - 1) * (sizeof(Base) * 8);

			std::bitset<sizeof(Base) * 8> bits(m_vals[m_vals.size() - 1]);

			size_t notSetBits = 0;
			for (auto bit = bits.size() - 1; bit >= 0; --bit)
			{
				if (!bits.test(bit))
				{
					notSetBits++;
				}
				else
				{
					break;
				}
				if (bit == 0)
				{
					break;
				}
			}
			count += ((sizeof(Base) * 8) - notSetBits);
			return count;
		}
		return 0;
	}

	bool IsBase2(uint64_t& base) const
	{
		uint64_t t = 0;
		if (IsZero())
		{
			return false;
		}

		bool bitFound = false;
		for (const Base v : m_vals)
		{
			std::bitset<sizeof(Base) * 8> bits(v);
			if (bitFound && bits.count() != 0)
			{
				return false;
			}
			else if (bits.count() > 1)
			{
				return false;
			}
			else if (bits.count() == 0)
			{
				if (!bitFound)
					t += sizeof(Base) * 8;
				continue;
			}
			else if (bits.count() == 1)
			{
				bitFound = true;
				for (size_t i = 0; i < bits.size(); ++i)
				{
					if (bits.test(i))
					{
						t += i;
						break;
					}
				}
			}
		}
		base = bitFound ? t : 0;
		return bitFound;
	}

	void CleanPreceedingZeroes()
	{
		for (auto i = m_vals.size() - 1; i > 0; --i)
		{
			if (m_vals[i] == 0)
			{
				m_vals.erase(m_vals.begin() + i);
			}
			else
			{
				break;
			}
		}
	}

	template<typename T>
	void FromNum(const T val)
	{
		const size_t chunks = sizeof(T) / sizeof(Base);
		m_vals.resize((chunks == 0 ? 1 : chunks), 0);
		for (size_t i = 0; i < m_vals.size(); ++i)
		{
			const auto shift = sizeof(Base) * 8 * i;
			m_vals[i] = Base(val >> shift);
		}
		CleanPreceedingZeroes();
	}

private:
	std::vector<Base> m_vals;
};