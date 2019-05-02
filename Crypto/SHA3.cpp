#include "SHA3.h"
#include <array>
#include <cassert>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <chrono>
#include <intrin.h>
#include <emmintrin.h>

namespace SHA3
{
namespace
{
constexpr const size_t ToBytes(const size_t bits) { return bits / 8ULL; };

static constexpr const uint8_t MATRIX_SIZE = 5U;
using Matrix = std::array<std::array<uint64_t, MATRIX_SIZE>, MATRIX_SIZE>;
using byte_t = uint8_t;

const constexpr uint8_t ITERATIONS = 24;
static constexpr const size_t STATE_SIZE = 1600ULL;
static constexpr const size_t STATE_SIZE_BYTES = ToBytes(STATE_SIZE);

inline void Theta(Matrix& A)
{
	const uint64_t C[MATRIX_SIZE]
	{
		A[0][0] ^ A[0][1] ^ A[0][2] ^ A[0][3] ^ A[0][4],
		A[1][0] ^ A[1][1] ^ A[1][2] ^ A[1][3] ^ A[1][4],
		A[2][0] ^ A[2][1] ^ A[2][2] ^ A[2][3] ^ A[2][4],
		A[3][0] ^ A[3][1] ^ A[3][2] ^ A[3][3] ^ A[3][4],
		A[4][0] ^ A[4][1] ^ A[4][2] ^ A[4][3] ^ A[4][4]
	};

	const uint64_t D[MATRIX_SIZE]
	{
		C[4] ^ __shiftleft128(C[1], C[1], 1),
		C[0] ^ __shiftleft128(C[2], C[2], 1),
		C[1] ^ __shiftleft128(C[3], C[3], 1),
		C[2] ^ __shiftleft128(C[4], C[4], 1),
		C[3] ^ __shiftleft128(C[0], C[0], 1)
	};

	for (size_t x = 0; x < MATRIX_SIZE; ++x)
	{
		for (size_t y = 0; y < MATRIX_SIZE; ++y)
		{
			A[x][y] ^= D[x];
		}
	}
};

inline void Rho(Matrix& A)
{
	size_t x = 1;
	size_t y = 0;
	for (size_t t = 0; t < ITERATIONS; ++t)
	{
		const auto offset = uint8_t(((t + 1) * (t + 2) / 2) % 64);
		A[x][y] = __shiftleft128(A[x][y], A[x][y], offset);

		const size_t tmp = y;
		y = (2 * x + 3 * y) % MATRIX_SIZE;
		x = tmp;
	};
};

inline void Pi(Matrix& A)
{
	const Matrix tmp = A;
	for (size_t x = 0; x < MATRIX_SIZE; ++x)
	{
		for (size_t y = 0; y < MATRIX_SIZE; ++y)
		{
			A[x][y] = tmp[(x + 3 * y) % MATRIX_SIZE][x];
		}
	}
};

inline void Chi(Matrix& A)
{
	const Matrix tmp = A;
	for (size_t x = 0; x < MATRIX_SIZE; ++x)
	{
		for (size_t y = 0; y < MATRIX_SIZE; ++y)
		{
			A[x][y] = tmp[x][y] ^ (~(tmp[(x + 1) % MATRIX_SIZE][y]) & tmp[(x + 2) % MATRIX_SIZE][y]);
		}
	}
};

inline void Iota(Matrix& A, const size_t round)
{
	constexpr const uint64_t RC[ITERATIONS]
	{
		0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL,
		0x8000000080008000ULL, 0x000000000000808BULL, 0x0000000080000001ULL,
		0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008AULL,
		0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
		0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL,
		0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
		0x000000000000800AULL, 0x800000008000000AULL, 0x8000000080008081ULL,
		0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
	};

	A[0][0] ^= RC[round];
};

inline void KeccakP(Matrix& A)
{
	for (size_t round = 0; round < ITERATIONS; ++round)
	{
		Theta(A);
		Rho(A);
		Pi(A);
		Chi(A);
		Iota(A, round);
	}
};

inline void NextIndex(size_t& x, size_t& y, size_t& i)
{
	if (++i != 8ULL)
	{
		return;
	}
	i = 0ULL;
	if (++x != MATRIX_SIZE)
	{
		return;
	}
	x = 0ULL;
	if (++y != MATRIX_SIZE)
	{
		return;
	}
}

template <typename InIter>
void Absorb(InIter first, InIter last, Matrix& A)
{
	size_t x = 0;
	size_t y = 0;
	size_t i = 0;
	for (; first != last && y < MATRIX_SIZE; ++first)
	{
		auto tmp = static_cast<uint64_t>(*first);
		A[x][y] ^= (tmp << (i * 8));
		NextIndex(x, y, i);
	};
}

template <typename OutIter>
inline OutIter DoSqueeze(const Matrix& A, OutIter first, OutIter last, const size_t rateBytes)
{
	size_t x = 0;
	size_t y = 0;
	size_t i = 0;
	for (size_t readBytes = 0;
		first != last && y < MATRIX_SIZE && readBytes < rateBytes;
		++readBytes, ++first)
	{
		auto tmp = static_cast<uint64_t>(A[x][y]);
		auto p = reinterpret_cast<byte_t*>(&tmp);
		*first = *(p + i);
		NextIndex(x, y, i);
	}
	return first;
};

template <typename InIter>
std::string BytesToHex(InIter begin, InIter end)
{
	std::stringstream ss;
	ss << std::hex;
	for (; begin != end; ++begin)
	{
		ss << std::setw(2) << std::setfill('0')
			<< static_cast<uint64_t>(*begin);
	}
	return ss.str();
}

template<Crypto::SHA3_Length SHA3>
class _SHA3Hasher
{
public:
	static constexpr const size_t SHA3_BYTES = static_cast<uint16_t>(SHA3);
	static constexpr const size_t SHA3_CAPACITY = SHA3_BYTES * 2U;
	static constexpr const size_t SHA3_RATEBYES = STATE_SIZE_BYTES - SHA3_CAPACITY;

	_SHA3Hasher()
		: m_hash {}
		, m_A {}
	{}

	inline void Process(std::filebuf* pBuffer)
	{
		const auto start = std::chrono::high_resolution_clock::now();
		constexpr int64_t bufferSize = SHA3_RATEBYES * 113; // Around 8kB
		std::array<byte_t, bufferSize> buffer{};
		auto bufferIterator = buffer.begin();
		auto chunkBegin = bufferIterator;
		auto chunkEnd = chunkBegin + SHA3_RATEBYES;

		uint64_t bytesRead = 0;

		auto AddPadding = [&buffer, &chunkBegin, &chunkEnd](const auto chunkIter)
		{
			const auto diff = SHA3_RATEBYES - std::distance(chunkBegin, chunkIter);
			if (diff == 1)
			{
				*chunkIter = 0x86;
			}
			else
			{
				*chunkIter = 0x06;
				*(chunkEnd - 1) = 0x80; // the last element of this chunk
			}
		};

		// Read a bigger chunk of data in a single operation
		bool lastIteration = false;
		bool firstIteration = true;
		while (!lastIteration)
		{
			std::streamsize inputLen = pBuffer->sgetn((char*)buffer.data(), bufferSize);
			bufferIterator = buffer.begin();

			if (!firstIteration && (inputLen < bufferSize))
			{
				// Buffer is not full, clear the buffer until the next chunk
				lastIteration = true;
				memset(buffer.data() + inputLen, 0, SHA3_RATEBYES - (inputLen % SHA3_RATEBYES));
			}

			bytesRead += inputLen;

			// Process data in chunks of SHA3_RATEBYTES
			while (inputLen >= 0)
			{
				if (!lastIteration && inputLen == 0)
					break;

				chunkBegin = bufferIterator;
				chunkEnd = chunkBegin + SHA3_RATEBYES;

				bufferIterator += SHA3_RATEBYES;

				if (inputLen < SHA3_RATEBYES)
				{
					// The very last chunk may (and likely is) not the size of SHA3_RATEBYTES
					// -> Add some padding
					AddPadding(chunkBegin + inputLen);
					lastIteration = true;
				}


				inputLen -= SHA3_RATEBYES;
				typename decltype(buffer)::const_iterator _cbegin = chunkBegin;
				typename decltype(buffer)::const_iterator _cend = chunkEnd;

				Absorb(_cbegin, _cend, m_A);
				KeccakP(m_A);
			}

			firstIteration = false;
		}

		Squeeze();

		const auto end = std::chrono::high_resolution_clock::now();
		const auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

		std::cout << "Hashing " << (bytesRead / 1024ULL) << "kB took: " << duration << "us" << std::endl;

		std::cout << "Hash: " << BytesToHex(m_hash.cbegin(), m_hash.cend()) << std::endl;

		std::cout << "Hash: " << BytesToHex(m_hash.crbegin(), m_hash.crend()) << std::endl;
	}

	inline void CopyToBuffer(char* pBuffer)
	{
		memcpy(pBuffer, m_hash.data(), SHA3_BYTES);
	}

private:
	inline void Squeeze()
	{
		auto first = m_hash.begin();
		const auto last = m_hash.end();
		first = DoSqueeze(m_A, first, last, SHA3_RATEBYES);
		while (first != last)
		{
			KeccakP(m_A);
			first = DoSqueeze(m_A, first, last, SHA3_RATEBYES);
		}
	}

private:
	std::array<byte_t, SHA3_BYTES> m_hash;
	Matrix m_A;
};
}

void SHA3Hasher::Process(const Crypto::SHA3_Length sha3, std::ifstream& ifs, char* hash)
{
	auto pBuffer = ifs.rdbuf();

	switch (sha3)
	{
	case Crypto::SHA3_Length::SHA3_224:
	{
		_SHA3Hasher<Crypto::SHA3_Length::SHA3_224> hasher;
		hasher.Process(pBuffer);
		hasher.CopyToBuffer(hash);
	}
	case Crypto::SHA3_Length::SHA3_256:
	{
		_SHA3Hasher<Crypto::SHA3_Length::SHA3_256> hasher;
		hasher.Process(pBuffer);
		hasher.CopyToBuffer(hash);
		break;
	}
	case Crypto::SHA3_Length::SHA3_384:
	{
		_SHA3Hasher<Crypto::SHA3_Length::SHA3_384> hasher;
		hasher.Process(pBuffer);
		hasher.CopyToBuffer(hash);
		break;
	}
	case Crypto::SHA3_Length::SHA3_512:
	{
		_SHA3Hasher<Crypto::SHA3_Length::SHA3_512> hasher;
		hasher.Process(pBuffer);
		hasher.CopyToBuffer(hash);
		break;
	}
	default:
		break;
	}
}
} // namespace SHA3
