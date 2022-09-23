#pragma once
#include "encryption_key_base.h"

#include <array>
#include <algorithm>
#include <cctype>
#include <stdexcept>

template <int NUM_BITS>
class encryption_key : public encryption_key_base
{
	static_assert(NUM_BITS == 128 || NUM_BITS == 192 || NUM_BITS == 256, "NUM_BITS must be one of {128, 192, 256}");
public:
	encryption_key();
	explicit encryption_key(const std::string& i_hex);
	void from_hex(const std::string& i_hex) override;
	std::string to_hex() const override;
	int num_of_bits_in_key() const override;
	const uint8_t* data() const override;
	virtual ~encryption_key() = default;
private:
	static constexpr int NUM_BYTES = NUM_BITS / 8;
	std::array<uint8_t, NUM_BYTES> m_key;
};

template <int NUM_BITS>
encryption_key<NUM_BITS>::encryption_key()
{
	std::fill(m_key.begin(), m_key.end(), 0);
}

template <int NUM_BITS>
encryption_key<NUM_BITS>::encryption_key(const std::string& i_hex)
{
	try
	{
		from_hex(i_hex);
	}
	catch (const std::exception& e)
	{
		throw(e);
	}
}

template <int NUM_BITS>
void encryption_key<NUM_BITS>::from_hex(const std::string& i_hex)
{
	if (!std::all_of(i_hex.cbegin(), i_hex.cend(), [](unsigned char c) {return std::isxdigit(c); }))
		throw std::invalid_argument("Incorrect key format. Format must be hexademical.");
	if (i_hex.length() != NUM_BYTES * 2)
		throw std::invalid_argument(("Incorrect key length: " + std::to_string(i_hex.length()) + " != " + std::to_string(NUM_BYTES << 1)).c_str());

	for (int i = 0; i < NUM_BYTES; ++i)
	{
		const char c0 = i_hex[i << 1];
		const char c1 = i_hex[1 + (i << 1)];
		m_key[i] =
			(uint8_t(c0 > 'a' ? (10 + c0 - 'a') : c0 > 'A' ? (10 + c0 - 'A') : c0 - '0') << 4) |
			(uint8_t(c1 > 'a' ? (10 + c1 - 'a') : c1 > 'A' ? (10 + c1 - 'A') : c1 - '0'));
	}
}

template <int NUM_BITS>
std::string encryption_key<NUM_BITS>::to_hex() const
{
	std::string ans(NUM_BYTES << 1, 0);
	for (int i = 0; i < (NUM_BYTES << 1); ++i)
	{
		const uint8_t num = m_key[i >> 1] & ((i & 1) ? 0x0F : 0xF0);
		ans[i] = num > 9 ? ('a' + char(num - 10)) : ('a' + char(num));
	}
	return ans;
}

template <int NUM_BITS>
int encryption_key<NUM_BITS>::num_of_bits_in_key() const
{
	return NUM_BITS;
}

template <int NUM_BITS>
const uint8_t* encryption_key<NUM_BITS>::data() const
{
	return m_key.data();
}