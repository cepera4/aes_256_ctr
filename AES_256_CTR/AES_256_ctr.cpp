#include "AES_256_ctr.h"

#include <array>
#include <chrono>
#include <thread>
#include <queue>
#include <cmath>
#include <stdexcept>

//anonymous ns
namespace
{
	/////////////////////////////////////////////////////////////////////////////////////////////////
	//common constants
	/////////////////////////////////////////////////////////////////////////////////////////////////
	constexpr int NUM_BITS_IN_KEY = 256;
	constexpr int NUM_BYTES_IN_KEY = NUM_BITS_IN_KEY / 8;
	constexpr int WORD_SZ = sizeof(uint32_t);
	constexpr int Nr = 14;
	constexpr int Nk = 8;
	constexpr int Nb = 4;
	constexpr int NUM_BYTES_IN_BLOCK = 16;

	constexpr std::array<uint8_t, 256> SBOX =
	{
		0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
		0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
		0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
		0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
		0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
		0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
		0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
		0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
		0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
		0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
		0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
		0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
		0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
		0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
		0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
	};

	using aes256_key_expanded = std::array<uint8_t, Nb* (Nr + 1)* WORD_SZ>;
	using aes_block = std::array<uint8_t, NUM_BYTES_IN_BLOCK>;
	/////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////

	/////////////////////////////////////////////////////////////////////////////////////////////////
	//key expansion
	/////////////////////////////////////////////////////////////////////////////////////////////////
	void rot_word(uint8_t* word) {
		const auto tmp = word[0];
		word[0] = word[1];
		word[1] = word[2];
		word[2] = word[3];
		word[3] = tmp;
	}

	void sub_word(uint8_t* word) {
		word[0] = SBOX[word[0]];
		word[1] = SBOX[word[1]];
		word[2] = SBOX[word[2]];
		word[3] = SBOX[word[3]];
	}

	inline void rot_word(uint32_t& word) {
		word = ((word >> 8) | (word << 24));
	}

	inline void sub_word(uint32_t& word) {
		sub_word(reinterpret_cast<uint8_t*>(&word));
	}

	void key256_expansion(const uint8_t* i_key, aes256_key_expanded& o_key_expanded)
	{
		constexpr std::array<uint32_t, 7> RCON = { 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, };

		uint32_t* key_as_words = reinterpret_cast<uint32_t*>(o_key_expanded.data());

		memcpy(key_as_words, i_key, NUM_BYTES_IN_KEY);

		uint32_t tmp;
		for (int i = Nk; i < Nb * (Nr + 1); ++i)
		{
			tmp = key_as_words[i - 1];
			if (i % Nk == 0)
			{
				rot_word(tmp);
				sub_word(tmp);
				tmp ^= RCON[(i / Nk) - 1];
			}
			else if (i % Nk == 4)
			{
				sub_word(tmp);
			}
			key_as_words[i] = key_as_words[i - Nk] ^ tmp;
		}
	}

	/////////////////////////////////////////////////////////////////////////////////////////////////
	//block encryption
	/////////////////////////////////////////////////////////////////////////////////////////////////
	using aes_state = uint8_t[4][4];

	constexpr uint8_t RG_field_mul2_impl(uint8_t x)
	{
		return (x >> 7) ? ((x << 1) ^ 0x1b) : (x << 1);
	}
	constexpr std::array<uint8_t, 256> calc_RG_field_mul2_arr()
	{
		std::array<uint8_t, 256> result{};
		for (uint8_t x = 0; x < 255; ++x)
			result[x] = RG_field_mul2_impl(x);

		result[255] = RG_field_mul2_impl(255);
		return result;
	}
	constexpr std::array<uint8_t, 256> RG_FIELD_MUL2_ARR = calc_RG_field_mul2_arr();

	inline uint8_t RG_field_mul2(uint8_t x) { return RG_FIELD_MUL2_ARR[x]; }

	/*
		https://en.wikipedia.org/wiki/Rijndael_MixColumns
		Mixing column r is multiplying it in Rijndael's Galois field with matrix:
		r[0]      \\   |2 3 1 1| |r[0]|
		r[1] ------\\  |1 2 3 1| |r[1]|
		r[2] ------//  |1 1 2 3| |r[2]|
		r[3]      //   |3 1 1 2| |r[3]|

		Multiplying x by 2 can be represented as (x >> 7) ? ((x << 1) ^ 0x1b) : (x << 1)
		Multiplying x by 3 is (mult_x_by2)^x

		Thus, mixing the row r can be represented as:
		row a = r; row b = mult_r_by2(r);
		r[0] = b[0] ^ a[3] ^ a[2] ^ b[1] ^ a[1];
		r[1] = b[1] ^ a[0] ^ a[3] ^ b[2] ^ a[2];
		r[2] = b[2] ^ a[1] ^ a[0] ^ b[3] ^ a[3];
		r[3] = b[3] ^ a[2] ^ a[1] ^ b[0] ^ a[0];

		Extra memory allocations with copying can be avoided by precalculating RG_field_mul2
		and keeping the first element and xored all elements from the row
	*/

	inline void mix_columns(aes_state& io_state)
	{
		uint8_t r0, row_xor;
		for (uint8_t i = 0; i < 4; ++i)
		{
			r0 = io_state[0][i];
			row_xor = io_state[0][i] ^ io_state[1][i] ^ io_state[2][i] ^ io_state[3][i];
			io_state[0][i] ^= RG_field_mul2(io_state[0][i] ^ io_state[1][i]) ^ row_xor;
			io_state[1][i] ^= RG_field_mul2(io_state[1][i] ^ io_state[2][i]) ^ row_xor;
			io_state[2][i] ^= RG_field_mul2(io_state[2][i] ^ io_state[3][i]) ^ row_xor;
			io_state[3][i] ^= RG_field_mul2(io_state[3][i] ^ r0) ^ row_xor;
		}
	}

	inline void shift_rows(uint32_t* io_block_as_words)
	{
		//row 0 is not rotated

		//rotate 1st row by 1 step left
		io_block_as_words[1] = ((io_block_as_words[1] >> (1 * 8)) | (io_block_as_words[1] << ((4 - 1) * 8)));

		//rotate 2nd row by 2 steps left
		io_block_as_words[2] = ((io_block_as_words[2] >> (2 * 8)) | (io_block_as_words[2] << ((4 - 2) * 8)));

		//rotate 3rd row by 3 steps left
		io_block_as_words[3] = ((io_block_as_words[3] >> (3 * 8)) | (io_block_as_words[3] << ((4 - 3) * 8)));
	}

	inline void sub_bytes(aes_block& io_block)
	{
		for (auto& b : io_block)
			b = SBOX[b];
	}

	inline void add_round_key(const uint32_t* i_key, uint32_t* io_words)
	{
		for (int i = 0; i < Nb; ++i)
			io_words[i] ^= i_key[i];
	}

	void encrypt_block(const aes256_key_expanded& i_key_expanded, aes_block& io_block)
	{
		const uint32_t* key_as_words = reinterpret_cast<const uint32_t*>(i_key_expanded.data());
		uint32_t* block_as_words = reinterpret_cast<uint32_t*>(io_block.data());

		add_round_key(key_as_words, block_as_words);

		aes_state& state = reinterpret_cast<aes_state&>(io_block._Elems);

		for (int i = 1; i < Nr; ++i)
		{
			sub_bytes(io_block);
			shift_rows(block_as_words);
			mix_columns(state);
			add_round_key(key_as_words + i * Nb, block_as_words);
		}

		sub_bytes(io_block);
		shift_rows(block_as_words);
		add_round_key(key_as_words + Nr * Nb, block_as_words);
	}
	/////////////////////////////////////////////////////////////////////////////////////////////////
	/////////////////////////////////////////////////////////////////////////////////////////////////
	auto make_ctr_block = [](const auto& nonce, const auto& counter, aes_block& o_block)
	{
		static_assert(sizeof(nonce) == 8, "nonce must be 64 bit");
		static_assert(sizeof(counter) == 8, "counter must be 64 bit");
		*((int64_t*)(o_block.data())) = *((int64_t*)(&counter));
		*(((int64_t*)(o_block.data())) + 1) = *((int64_t*)(&nonce));
	};
}
//end of anonymous ns


/////////////////////////////////////////////////////////////////////////////////////////////////
//class implementation
/////////////////////////////////////////////////////////////////////////////////////////////////
AES_256_ctr::AES_256_ctr(std::shared_ptr<encryption_key_base const> i_key, std::optional<int64_t> i_nonce) :
	m_processed_blocks(0),
	m_key(std::move(i_key)),
	m_nonce(i_nonce ? i_nonce.value() : std::chrono::high_resolution_clock::now().time_since_epoch().count())
{
	if (m_key->num_of_bits_in_key() != NUM_BITS_IN_KEY)
		throw std::invalid_argument(("Key must be " + std::to_string(NUM_BITS_IN_KEY) + " bits long").c_str());
}

int64_t AES_256_ctr::get_nonce() const { return m_nonce; }

void AES_256_ctr::encrypt(std::vector<uint8_t>& io_data)
{
	aes256_key_expanded key_expanded;
	key256_expansion(m_key->data(), key_expanded);

	//encrypting blocks multithreaded
	const int blocks_num = static_cast<int>(std::ceil(float(io_data.size()) / NUM_BYTES_IN_BLOCK));
	std::queue<std::thread> q;
	for (unsigned tid = 0; tid < std::thread::hardware_concurrency(); ++tid)
		q.emplace(
			[this, &blocks_num, &key_expanded, &io_data, tid = tid]() {
		aes_block ctr_block;
		for (int i = tid; i < blocks_num; i += std::thread::hardware_concurrency()) {
			const int num_bytes =
				(i != blocks_num - 1) ? NUM_BYTES_IN_BLOCK :
				((io_data.size() % NUM_BYTES_IN_BLOCK) == 0) ? NUM_BYTES_IN_BLOCK : static_cast<int>(io_data.size()) % NUM_BYTES_IN_BLOCK;

			make_ctr_block(m_nonce, m_processed_blocks + i, ctr_block);
			encrypt_block(key_expanded, ctr_block);
			for (int j = 0; j < num_bytes; ++j)
				io_data[i * num_bytes + j] = ctr_block[j] ^ io_data[i * num_bytes + j];
		}
	});
	while (!q.empty()) {
		q.front().join();
		q.pop();
	}
	m_processed_blocks += blocks_num;
}

void AES_256_ctr::decrypt(std::vector<uint8_t>& io_data)
{
	try
	{
		encrypt(io_data);
	}
	catch (const std::exception& e)
	{
		throw(e);
	}
}
