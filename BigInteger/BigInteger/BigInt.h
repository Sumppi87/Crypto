#pragma once
#include <type_traits>
#include <vector>
#include <string>

namespace
{
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
		/*
		const MulUtil<Base, Mul> sum((Mul)res[index] + (Mul)mul.valLower);
		if (sum.carryOver)
		{
			const MulUtil<Base, Mul> t((Mul)res[index + 1] + (Mul)sum.carryOver);
			AddResult(res, t, index + 1);
		}
		else
		{
			const MulUtil<Base, Mul> t((Mul)res[index] + (Mul)sum.valLower);
			res[index] = t.valLower;

			if (t.carryOver)
			{
				AddResult(res, MulUtil<Base, Mul>(t.carryOver), index + 1);
			}
		}*/
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

	BigInt& operator*(const BigInt other)
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

	std::string toHex() const
	{
		std::string ret;
		ret.append("0x");
		for (int i = m_vals.size() - 1; i >= 0; --i)
		{
			for (int quadNro = (sizeof(Base) * 2) - 1; quadNro >= 0; --quadNro)
			{
				const Base mask = (0xF << (quadNro * 4));
				const int quad = (m_vals[i] & mask) >> (quadNro * 4);
				switch (quad)
				{
				case 0:
					ret.append("0");
					break;
				case 1:
					ret.append("1");
					break;
				case 2:
					ret.append("2");
					break;
				case 3:
					ret.append("3");
					break;
				case 4:
					ret.append("4");
					break;
				case 5:
					ret.append("5");
					break;
				case 6:
					ret.append("6");
					break;
				case 7:
					ret.append("7");
					break;
				case 8:
					ret.append("8");
					break;
				case 9:
					ret.append("9");
					break;
				case 10:
					ret.append("A");
					break;
				case 11:
					ret.append("B");
					break;
				case 12:
					ret.append("C");
					break;
				case 13:
					ret.append("D");
					break;
				case 14:
					ret.append("E");
					break;
				case 15:
					ret.append("F");
					break;
				default:
					break;
				}
			}
		}
		return ret;
	}

private:
	std::vector<Base> m_vals;
};