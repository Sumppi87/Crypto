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
	uint8_t CharToNum(const char c)
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
	void AddResult(std::vector<Base>& res, const MulUtil<Base, Mul> mul, const int index)
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
	BigInt()
	{
		m_vals.push_back(0);
	}

	BigInt(const BigInt& other)
		: m_vals(other.m_vals)
	{

	}

	BigInt(const Base val)
	{
		m_vals.push_back(val);
	}

	BigInt(const Mul val)
	{
		MulUtil<Base, Mul> temp(val);
		m_vals.push_back(temp.valLower);
		if (temp.carryOver)
		{
			m_vals.push_back(temp.carryOver);
		}
	}

	BigInt(const char* hex)
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
			int index =  2;
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

		std::div_t res = std::div(int(length - ignoreFrom), int((sizeof(Base) * 2)));
		const size_t neededSize = res.rem == 0 ? res.quot : res.quot + 1;
		m_vals.resize(neededSize, 0);

		for (size_t i = length - 1; i >= ignoreFrom; --i)
		{
			const std::div_t res = std::div(int((length - 1) - i), int(sizeof(Base) * 2));
			const size_t index = res.quot;
			const size_t shift = res.rem * 4;
			auto val = CharToNum(hex[i]);
			const Base shifted = (val << shift);
			m_vals[index] += shifted;
			if (i == 0)
			{
				break;
			}
		}
	}

	BigInt operator+(const BigInt& other) const
	{
		if (!other.m_vals.empty())
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
		if (other.m_vals.size() > m_vals.size())
		{
			throw std::logic_error("Decrement would overflow");
		}

		const auto s = std::max(m_vals.size(), other.m_vals.size()) + 1;
		BigInt copy;
		copy.m_vals.resize(s, 0);
		const size_t size = m_vals.size();
		const size_t size2 = other.m_vals.size();

		for (size_t i = 0; i < copy.m_vals.size(); ++i)
		{
			const Base val1 = ~Base(i < size ? m_vals[i] : 0);
			const Base val2 = Base(i < size2 ? other.m_vals[i] : 0);
			MulUtil<Base, Mul> sum(val1 + val2);
			AddResult(copy.m_vals, sum, i);

			copy.m_vals[i] = ~copy.m_vals[i];
		}

		copy.CleanPreceedingZeroes();

		return copy;
	}

	BigInt operator%(const BigInt& other) const
	{
		if (other.m_vals.size() > m_vals.size()
			|| *this < other)
		{
			return *this;
		}

		BigInt remainder(*this);

		while (remainder > other)
		{
			const uint64_t shift = remainder.GetBitWidth() - other.GetBitWidth();
			BigInt divisor = other << shift;
			if (divisor >= remainder)
			{
				divisor = divisor >> 1;
			}
			remainder = remainder - divisor;
		}
		return remainder;
	}

	BigInt operator/(const BigInt& other) const
	{
		if (other.m_vals.size() == 0
			|| (other.m_vals.size() == 1
				&& other.m_vals[0] == 0))
		{
			throw std::invalid_argument("Division by zero");
		}

		uint64_t base = 0;
		if (other.IsBase2(base))
		{
			// If the divisor is base-2, a simple shift will do
			return *this >> base;
		}
		
		BigInt remainder(*this);
		BigInt quot;

		while (remainder > other)
		{
			uint64_t shift = remainder.GetBitWidth() - other.GetBitWidth();
			BigInt divisor = other << shift;
			if (divisor >= remainder)
			{
				divisor = divisor >> 1;
				--shift;
			}
			quot = quot + BigInt(Base(1)) << shift;
			remainder = remainder - divisor;
		}
		return quot;
	}

	BigInt operator*(const BigInt& other) const
	{
		if (other.m_vals.empty() || m_vals.empty())
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

	BigInt operator<<(const uint64_t shift) const
	{
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
		BigInt copy;

		const auto quot = (shift / (sizeof(Base) * 8));
		const auto rem = (shift % (sizeof(Base) * 8));
		if (rem >= m_vals.size())
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
			for (size_t i = m_vals.size() - 1; i <= 0; --i)
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
		return !(*this >= other);
	}

	bool operator<(const BigInt& other) const
	{
		return !(*this > other);
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
		std::string ret;
		ret.append("0x");
		bool nonZeroAdded = false;
		for (int i = m_vals.size() - 1; i >= 0; --i)
		{
			for (int quadNro = (sizeof(Base) * 2) - 1; quadNro >= 0; --quadNro)
			{
				const Base mask = (0xF << (quadNro * 4));
				const int quad = (m_vals[i] & mask) >> (quadNro * 4);
				if (!nonZeroAdded && quad == 0)
				{
					continue;
				}
				nonZeroAdded = true;
				ret += NumToChar(quad);
			}
		}
		if (!nonZeroAdded)
		{
			ret += NumToChar(0);
		}
		return ret;
	}

private:
	uint64_t GetBitWidth() const
	{
		if (m_vals.size() > 0)
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
		if (m_vals.size() == 0)
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

private:
	std::vector<Base> m_vals;
};