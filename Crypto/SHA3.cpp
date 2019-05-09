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

namespace
{
constexpr const size_t ToBytes(const size_t bits) { return bits / 8ULL; };

static constexpr const uint8_t MATRIX_SIZE = 5U;
using Matrix = std::array<std::array<uint64_t, MATRIX_SIZE>, MATRIX_SIZE>;

const constexpr uint8_t ITERATIONS = 24;

static constexpr const size_t STATE_SIZE = 1600ULL;
static constexpr const uint8_t STATE_SIZE_BYTES = ToBytes(STATE_SIZE);

using byte_t = uint8_t;

inline uint64_t RotateLeft(const uint64_t value, const uint8_t rotation)
{
	return __shiftleft128(value, value, rotation);
}

inline void NextIndex(uint8_t& x, uint8_t& y, uint8_t& i)
{
	if (++i != 8U)
	{
		return;
	}
	i = 0U;
	if (++x != MATRIX_SIZE)
	{
		return;
	}
	x = 0U;
	if (++y != MATRIX_SIZE)
	{
		return;
	}
}

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

template <uint8_t RATE_BYTES>
class Sponge
{
public:
	Sponge()
		: m_sponge{} {}

	template <typename InIter>
	void Absorb(InIter first, InIter last)
	{
		uint8_t x = 0;
		uint8_t y = 0;
		uint8_t i = 0;
		for (; first != last && y < MATRIX_SIZE; ++first)
		{
			auto tmp = static_cast<uint64_t>(*first);
			m_sponge[x][y] ^= (tmp << (i * 8));
			NextIndex(x, y, i);
		}

		KeccakP();
	}

	template <typename InIter>
	inline void Squeeze(InIter first, InIter last)
	{
		first = DoSqueeze(first, last);
		while (first != last)
		{
			KeccakP();
			first = DoSqueeze(first, last);
		}
	}

private:
	inline void KeccakP()
	{
		for (uint8_t round = 0; round < ITERATIONS; ++round)
		{
			Theta();
			Rho();
			Pi();
			Chi();
			Iota(round);
		}
	}

	template <typename OutIter>
	inline OutIter DoSqueeze(OutIter first, OutIter last)
	{
		uint8_t x = 0;
		uint8_t y = 0;
		uint8_t i = 0;
		for (uint8_t readBytes = 0;
			first != last && y < MATRIX_SIZE && readBytes < RATE_BYTES;
			++readBytes, ++first)
		{
			auto tmp = static_cast<uint64_t>(m_sponge[x][y]);
			auto p = reinterpret_cast<byte_t*>(&tmp);
			*first = *(p + i);
			NextIndex(x, y, i);
		}
		return first;
	}

	inline void Theta()
	{
		const uint64_t C[MATRIX_SIZE]
		{
			m_sponge[0][0] ^ m_sponge[0][1] ^ m_sponge[0][2] ^ m_sponge[0][3] ^ m_sponge[0][4],
			m_sponge[1][0] ^ m_sponge[1][1] ^ m_sponge[1][2] ^ m_sponge[1][3] ^ m_sponge[1][4],
			m_sponge[2][0] ^ m_sponge[2][1] ^ m_sponge[2][2] ^ m_sponge[2][3] ^ m_sponge[2][4],
			m_sponge[3][0] ^ m_sponge[3][1] ^ m_sponge[3][2] ^ m_sponge[3][3] ^ m_sponge[3][4],
			m_sponge[4][0] ^ m_sponge[4][1] ^ m_sponge[4][2] ^ m_sponge[4][3] ^ m_sponge[4][4]
		};

		const uint64_t D[MATRIX_SIZE]
		{
			C[4] ^ RotateLeft(C[1], 1),
			C[0] ^ RotateLeft(C[2], 1),
			C[1] ^ RotateLeft(C[3], 1),
			C[2] ^ RotateLeft(C[4], 1),
			C[3] ^ RotateLeft(C[0], 1)
		};

		/*for (uint8_t x = 0; x < MATRIX_SIZE; ++x)
		{
			for (uint8_t y = 0; y < MATRIX_SIZE; ++y)
			{
				m_sponge[x][y] ^= D[x];
			}
		}*/
		// Expand for-loops
		m_sponge[0][0] ^= D[0];
		m_sponge[0][1] ^= D[0];
		m_sponge[0][2] ^= D[0];
		m_sponge[0][3] ^= D[0];
		m_sponge[0][4] ^= D[0];

		m_sponge[1][0] ^= D[1];
		m_sponge[1][1] ^= D[1];
		m_sponge[1][2] ^= D[1];
		m_sponge[1][3] ^= D[1];
		m_sponge[1][4] ^= D[1];

		m_sponge[2][0] ^= D[2];
		m_sponge[2][1] ^= D[2];
		m_sponge[2][2] ^= D[2];
		m_sponge[2][3] ^= D[2];
		m_sponge[2][4] ^= D[2];

		m_sponge[3][0] ^= D[3];
		m_sponge[3][1] ^= D[3];
		m_sponge[3][2] ^= D[3];
		m_sponge[3][3] ^= D[3];
		m_sponge[3][4] ^= D[3];

		m_sponge[4][0] ^= D[4];
		m_sponge[4][1] ^= D[4];
		m_sponge[4][2] ^= D[4];
		m_sponge[4][3] ^= D[4];
		m_sponge[4][4] ^= D[4];
	};

	inline void Rho()
	{
		// Precalculate values of 'x' and 'y', and 'offset' for each iteration
		/*
		for (uint8_t t = 0; t < ITERATIONS; ++t)
		{
			const auto offset = uint8_t(((t + 1) * (t + 2) / 2) % 64);

			uint8_t x = 1;
			uint8_t y = 0;
			const uint8_t tmp = y;
			y = (2U * x + 3U * y) % MATRIX_SIZE;
			x = tmp;
		}
		*/

		const constexpr uint8_t OFFSETS[ITERATIONS]{ 1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44 };
		const constexpr uint8_t X[ITERATIONS] { 1, 0, 2, 1, 2, 3, 3, 0, 1, 3, 1, 4, 4, 0, 3, 4, 3, 2, 2, 0, 4, 2, 4, 1 };
		const constexpr uint8_t Y[ITERATIONS] { 0, 2, 1, 2, 3, 3, 0, 1, 3, 1, 4, 4, 0, 3, 4, 3, 2, 2, 0, 4, 2, 4, 1, 1 };

		/*for (uint8_t t = 0; t < ITERATIONS; ++t)
		{
			const uint8_t x = X[t];
			const uint8_t y = Y[t];
			m_sponge[x][y] = RotateLeft(m_sponge[x][y], OFFSETS[t]);
		};*/
		// Expand the for-loop
		m_sponge[X[0]][Y[0]] = RotateLeft(m_sponge[X[0]][Y[0]], OFFSETS[0]);
		m_sponge[X[1]][Y[1]] = RotateLeft(m_sponge[X[1]][Y[1]], OFFSETS[1]);
		m_sponge[X[2]][Y[2]] = RotateLeft(m_sponge[X[2]][Y[2]], OFFSETS[2]);
		m_sponge[X[3]][Y[3]] = RotateLeft(m_sponge[X[3]][Y[3]], OFFSETS[3]);
		m_sponge[X[4]][Y[4]] = RotateLeft(m_sponge[X[4]][Y[4]], OFFSETS[4]);
		m_sponge[X[5]][Y[5]] = RotateLeft(m_sponge[X[5]][Y[5]], OFFSETS[5]);
		m_sponge[X[6]][Y[6]] = RotateLeft(m_sponge[X[6]][Y[6]], OFFSETS[6]);
		m_sponge[X[7]][Y[7]] = RotateLeft(m_sponge[X[7]][Y[7]], OFFSETS[7]);
		m_sponge[X[8]][Y[8]] = RotateLeft(m_sponge[X[8]][Y[8]], OFFSETS[8]);
		m_sponge[X[9]][Y[9]] = RotateLeft(m_sponge[X[9]][Y[9]], OFFSETS[9]);
		m_sponge[X[10]][Y[10]] = RotateLeft(m_sponge[X[10]][Y[10]], OFFSETS[10]);
		m_sponge[X[11]][Y[11]] = RotateLeft(m_sponge[X[11]][Y[11]], OFFSETS[11]);
		m_sponge[X[12]][Y[12]] = RotateLeft(m_sponge[X[12]][Y[12]], OFFSETS[12]);
		m_sponge[X[13]][Y[13]] = RotateLeft(m_sponge[X[13]][Y[13]], OFFSETS[13]);
		m_sponge[X[14]][Y[14]] = RotateLeft(m_sponge[X[14]][Y[14]], OFFSETS[14]);
		m_sponge[X[15]][Y[15]] = RotateLeft(m_sponge[X[15]][Y[15]], OFFSETS[15]);
		m_sponge[X[16]][Y[16]] = RotateLeft(m_sponge[X[16]][Y[16]], OFFSETS[16]);
		m_sponge[X[17]][Y[17]] = RotateLeft(m_sponge[X[17]][Y[17]], OFFSETS[17]);
		m_sponge[X[18]][Y[18]] = RotateLeft(m_sponge[X[18]][Y[18]], OFFSETS[18]);
		m_sponge[X[19]][Y[19]] = RotateLeft(m_sponge[X[19]][Y[19]], OFFSETS[19]);
		m_sponge[X[20]][Y[20]] = RotateLeft(m_sponge[X[20]][Y[20]], OFFSETS[20]);
		m_sponge[X[21]][Y[21]] = RotateLeft(m_sponge[X[21]][Y[21]], OFFSETS[21]);
		m_sponge[X[22]][Y[22]] = RotateLeft(m_sponge[X[22]][Y[22]], OFFSETS[22]);
		m_sponge[X[23]][Y[23]] = RotateLeft(m_sponge[X[23]][Y[23]], OFFSETS[23]);
	};

	inline void Pi()
	{
		// Precalculated index
		// using formula: (x + 3U * y) % MATRIX_SIZE
		const constexpr uint8_t INDEX[MATRIX_SIZE][MATRIX_SIZE]
		{
			{ 0, 3, 1, 4, 2 },
			{ 1, 4, 2, 0, 3 },
			{ 2, 0, 3, 1, 4 },
			{ 3, 1, 4, 2, 0 },
			{ 4, 2, 0, 3, 1 }
		};

		const Matrix tmp = m_sponge;

		// Expand loop
		/*for (uint8_t x = 0; x < MATRIX_SIZE; ++x)
		{
			for (uint8_t y = 0; y < MATRIX_SIZE; ++y)
			{
				const uint8_t index = INDEX[x][y];
				m_sponge[x][y] = tmp[INDEX[x][y]][x];
			}
		}*/
		m_sponge[0][0] = tmp[INDEX[0][0]][0];
		m_sponge[0][1] = tmp[INDEX[0][1]][0];
		m_sponge[0][2] = tmp[INDEX[0][2]][0];
		m_sponge[0][3] = tmp[INDEX[0][3]][0];
		m_sponge[0][4] = tmp[INDEX[0][4]][0];

		m_sponge[1][0] = tmp[INDEX[1][0]][1];
		m_sponge[1][1] = tmp[INDEX[1][1]][1];
		m_sponge[1][2] = tmp[INDEX[1][2]][1];
		m_sponge[1][3] = tmp[INDEX[1][3]][1];
		m_sponge[1][4] = tmp[INDEX[1][4]][1];

		m_sponge[2][0] = tmp[INDEX[2][0]][2];
		m_sponge[2][1] = tmp[INDEX[2][1]][2];
		m_sponge[2][2] = tmp[INDEX[2][2]][2];
		m_sponge[2][3] = tmp[INDEX[2][3]][2];
		m_sponge[2][4] = tmp[INDEX[2][4]][2];

		m_sponge[3][0] = tmp[INDEX[3][0]][3];
		m_sponge[3][1] = tmp[INDEX[3][1]][3];
		m_sponge[3][2] = tmp[INDEX[3][2]][3];
		m_sponge[3][3] = tmp[INDEX[3][3]][3];
		m_sponge[3][4] = tmp[INDEX[3][4]][3];

		m_sponge[4][0] = tmp[INDEX[4][0]][4];
		m_sponge[4][1] = tmp[INDEX[4][1]][4];
		m_sponge[4][2] = tmp[INDEX[4][2]][4];
		m_sponge[4][3] = tmp[INDEX[4][3]][4];
		m_sponge[4][4] = tmp[INDEX[4][4]][4];
	};

	inline void Chi()
	{
		// Precalculated 1. index: (x + 1) % MATRIX_SIZE]
		const constexpr uint8_t IDX_1[MATRIX_SIZE]{ 1, 2, 3, 4, 0 };
		// Precalculated 2. index: (x + 2) % MATRIX_SIZE]
		const constexpr uint8_t IDX_2[MATRIX_SIZE]{ 2, 3, 4, 0, 1 };

		const Matrix tmp = m_sponge;
		/*for (uint8_t x = 0; x < MATRIX_SIZE; ++x)
		{
			for (uint8_t y = 0; y < MATRIX_SIZE; ++y)
			{
				const uint8_t idx1 = IDX_1[x];
				const uint8_t idx2 = IDX_2[x];
				m_sponge[x][y] = tmp[x][y] ^ (~(tmp[idx1][y]) & tmp[idx2][y]);
			}
		}*/
		/* Expand the loops */
		m_sponge[0][0] = tmp[0][0] ^ (~(tmp[IDX_1[0]][0]) & tmp[IDX_2[0]][0]);
		m_sponge[0][1] = tmp[0][1] ^ (~(tmp[IDX_1[0]][1]) & tmp[IDX_2[0]][1]);
		m_sponge[0][2] = tmp[0][2] ^ (~(tmp[IDX_1[0]][2]) & tmp[IDX_2[0]][2]);
		m_sponge[0][3] = tmp[0][3] ^ (~(tmp[IDX_1[0]][3]) & tmp[IDX_2[0]][3]);
		m_sponge[0][4] = tmp[0][4] ^ (~(tmp[IDX_1[0]][4]) & tmp[IDX_2[0]][4]);

		m_sponge[1][0] = tmp[1][0] ^ (~(tmp[IDX_1[1]][0]) & tmp[IDX_2[1]][0]);
		m_sponge[1][1] = tmp[1][1] ^ (~(tmp[IDX_1[1]][1]) & tmp[IDX_2[1]][1]);
		m_sponge[1][2] = tmp[1][2] ^ (~(tmp[IDX_1[1]][2]) & tmp[IDX_2[1]][2]);
		m_sponge[1][3] = tmp[1][3] ^ (~(tmp[IDX_1[1]][3]) & tmp[IDX_2[1]][3]);
		m_sponge[1][4] = tmp[1][4] ^ (~(tmp[IDX_1[1]][4]) & tmp[IDX_2[1]][4]);

		m_sponge[2][0] = tmp[2][0] ^ (~(tmp[IDX_1[2]][0]) & tmp[IDX_2[2]][0]);
		m_sponge[2][1] = tmp[2][1] ^ (~(tmp[IDX_1[2]][1]) & tmp[IDX_2[2]][1]);
		m_sponge[2][2] = tmp[2][2] ^ (~(tmp[IDX_1[2]][2]) & tmp[IDX_2[2]][2]);
		m_sponge[2][3] = tmp[2][3] ^ (~(tmp[IDX_1[2]][3]) & tmp[IDX_2[2]][3]);
		m_sponge[2][4] = tmp[2][4] ^ (~(tmp[IDX_1[2]][4]) & tmp[IDX_2[2]][4]);

		m_sponge[3][0] = tmp[3][0] ^ (~(tmp[IDX_1[3]][0]) & tmp[IDX_2[3]][0]);
		m_sponge[3][1] = tmp[3][1] ^ (~(tmp[IDX_1[3]][1]) & tmp[IDX_2[3]][1]);
		m_sponge[3][2] = tmp[3][2] ^ (~(tmp[IDX_1[3]][2]) & tmp[IDX_2[3]][2]);
		m_sponge[3][3] = tmp[3][3] ^ (~(tmp[IDX_1[3]][3]) & tmp[IDX_2[3]][3]);
		m_sponge[3][4] = tmp[3][4] ^ (~(tmp[IDX_1[3]][4]) & tmp[IDX_2[3]][4]);

		m_sponge[4][0] = tmp[4][0] ^ (~(tmp[IDX_1[4]][0]) & tmp[IDX_2[4]][0]);
		m_sponge[4][1] = tmp[4][1] ^ (~(tmp[IDX_1[4]][1]) & tmp[IDX_2[4]][1]);
		m_sponge[4][2] = tmp[4][2] ^ (~(tmp[IDX_1[4]][2]) & tmp[IDX_2[4]][2]);
		m_sponge[4][3] = tmp[4][3] ^ (~(tmp[IDX_1[4]][3]) & tmp[IDX_2[4]][3]);
		m_sponge[4][4] = tmp[4][4] ^ (~(tmp[IDX_1[4]][4]) & tmp[IDX_2[4]][4]);
	}

	inline void Iota(const uint8_t round)
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

		m_sponge[0][0] ^= RC[round];
	}

private:
	Matrix m_sponge;
};

template<Crypto::SHA3_Length SHA3>
class _SHA3Hasher
{
public:
	static constexpr const uint8_t SHA3_BYTES = static_cast<uint16_t>(SHA3);
	static constexpr const uint8_t SHA3_CAPACITY = SHA3_BYTES * 2U;
	static constexpr const uint8_t SHA3_RATEBYES = STATE_SIZE_BYTES - SHA3_CAPACITY;

	_SHA3Hasher()
		: m_hash{}
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

				m_sponge.Absorb(_cbegin, _cend);
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
		m_sponge.Squeeze(first, last);
	}

private:
	std::array<byte_t, SHA3_BYTES> m_hash;
	Sponge<SHA3_RATEBYES> m_sponge;
};
}

namespace SHA3
{
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
