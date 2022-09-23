#pragma once
#include <string>

class encryption_key_base
{
public:
	virtual void from_hex(const std::string& i_hex) = 0;
	virtual std::string to_hex() const = 0;
	virtual int num_of_bits_in_key() const = 0;
	virtual ~encryption_key_base() = default;
	virtual const uint8_t* data() const = 0;
};