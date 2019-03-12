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
		if (mul.carryOver)
		{
			const MulUtil<Base, Mul> t((Mul)res[index + 1] + (Mul)mul.carryOver);
			res[index + 1] = t.valLower;
			if (t.carryOver)
			{
				AddResult(res, MulUtil<Base, Mul>(t.carryOver), index + 1);
			}
		}
		//else
		{
			const MulUtil<Base, Mul> t((Mul)res[index] + (Mul)mul.valLower);
			res[index] = t.valLower;
			
			if (t.carryOver)
			{
				AddResult(res, MulUtil<Base, Mul>(t.carryOver), index + 1);
			}
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

	BigInt(const Base val)
	{
		m_vals.push_back(val);
	}

	BigInt(const Mul val)
	{
		MulUtil<Base, Mul> temp(val);
		m_vals.push_back(temp.valLower);
		m_vals.push_back(temp.carryOver);
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
		/*if (hex[0] != '0' && hex[1] != 'x')
		{
			throw std::invalid_argument("Not a valid hexadecimal");
		}*/

		const size_t ignoreFrom = [hex, length]()
		{
			int index = (hex[0] == '0' && hex[1] == 'x') ? 2 : 0;
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

	BigInt& operator+(const BigInt& other)
	{
		if (!other.m_vals.empty())
		{
			const auto s = std::max(m_vals.size(), other.m_vals.size()) + 1;
			std::vector<Base> res;
			res.resize(s, 0);
			const size_t size = m_vals.size();
			const size_t size2 = other.m_vals.size();

			for (size_t i = 0; i < size || i < size2; ++i)
			{
				const Mul val1 = i < size ? m_vals[i] : 0;
				const Mul val2 = i < size2 ? other.m_vals[i] : 0;
				MulUtil<Base, Mul> sum(val1 + val2);
				AddResult(res, sum, i);
			}

			if (res[res.size() - 1] == 0)
			{
				res.erase(res.begin() + (res.size() - 1));
			}

			m_vals = res;
		}
		return *this;
	}

	BigInt& operator-(const BigInt& other)
	{
		if (other.m_vals.size() > m_vals.size())
		{
			throw std::logic_error("Decrement would overflow");
		}

		const auto s = std::max(m_vals.size(), other.m_vals.size()) + 1;
		std::vector<Base> res;
		res.resize(s, 0);
		const size_t size = m_vals.size();
		const size_t size2 = other.m_vals.size();

		for (size_t i = 0; i < res.size(); ++i)
		{
			const Base val1 = ~Base(i < size ? m_vals[i] : 0);
			const Base val2 = Base(i < size2 ? other.m_vals[i] : 0);
			MulUtil<Base, Mul> sum(val1 + val2);
			AddResult(res, sum, i);

			res[i] = ~res[i];
		}

		for (auto i = res.size() - 1; i >= 0; --i)
		{
			if (res[i] == 0)
			{
				if (res.size() == 1)
				{
					break;
				}
				res.erase(res.begin() + i);
			}
			else
			{
				break;
			}
		}

		m_vals = res;
		return *this;
	}

	BigInt& operator%(const BigInt& other)
	{
		if (other.m_vals.size() > m_vals.size()
			|| *this < other)
		{
			return *this;
		}

		const uint64_t bitCount = GetBitCount() - other.GetBitCount();
		const auto chunks = 1 + ((bitCount - 1) / (sizeof(Base) * 8));
		
		const size_t shift = size_t((bitCount % chunks) - 1);

		BigInt copy;
		copy.m_vals.resize(size_t(chunks), 0);
		Base value = Base(1 << shift);
		copy.m_vals[size_t(chunks) - 1] = value;
		/*while ((*this) >= other)
		{
			(*this) - other;
		}*/
		return *this;
	}

	BigInt& operator*(const BigInt& other)
	{
		if (other.m_vals.empty() || m_vals.empty())
		{
			m_vals.clear();
		}
		else
		{
			const auto s = m_vals.size() + other.m_vals.size();
			std::vector<Base> res;
			res.resize(s, 0);

			const std::vector<Base>& multiplier = m_vals.size() <= other.m_vals.size() ? m_vals : other.m_vals;
			const std::vector<Base>& multiplied = m_vals.size() > other.m_vals.size() ? m_vals : other.m_vals;

			for (size_t i = 0; i < multiplier.size(); ++i)
			{
				for (size_t ii = 0; ii < multiplied.size(); ++ii)
				{
					MulUtil<Base, Mul> mul((Mul)multiplier[i] * (Mul)multiplied[ii]);
					AddResult(res, mul, i + ii);
				}
			}

			for (auto i = res.size() - 1; i >= 0; --i)
			{
				if (res[i] == 0)
				{
					res.erase(res.begin() + i);
				}
				else
				{
					break;
				}
			}

			m_vals = res;
		}
		return *this;
	}

	bool operator>(const BigInt& other)
	{
		bool bigger = true;
		if (m_vals.size() == other.m_vals.size())
		{
			for (size_t i = m_vals.size() - 1; i <= 0; --i)
			{
				if (!(m_vals[i] > other.m_vals[i]))
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
			bigger = m_vals.size() > other.m_vals.size();
		}
		return bigger;
	}

	bool operator>=(const BigInt& other)
	{
		bool greaterOrEqual = true;
		if (m_vals.size() == other.m_vals.size())
		{
			for (size_t i = m_vals.size() - 1; i <= 0; --i)
			{
				if (!(m_vals[i] >= other.m_vals[i]))
				{
					greaterOrEqual = false;
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
			greaterOrEqual = m_vals.size() > other.m_vals.size();
		}
		return greaterOrEqual;
	}

	bool operator<=(const BigInt& other)
	{
		return !(*this >= other);
	}

	bool operator<(const BigInt& other)
	{
		return !(*this > other);
	}

	bool operator!=(const BigInt& other)
	{
		return !(*this == other);
	}

	bool operator==(const BigInt& other)
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
	uint64_t GetBitCount() const
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

	std::vector<Base> m_vals;
};