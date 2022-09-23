#pragma once

#include "encryption_key_base.h"

#include <memory>
#include <istream>
#include <ostream>

enum class encryption_mode { e_encrypt, e_decrypt };

struct encryption_settings
{
	std::istream& istr;
	std::ostream& ostr;
	const std::shared_ptr<encryption_key_base const> m_key;
	encryption_mode m_mode;
};