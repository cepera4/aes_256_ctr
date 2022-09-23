#pragma once
#include "encryption_settings.h"

class stream_encryptor
{
public:
	static void encrypt(std::shared_ptr<const encryption_settings> i_settings, int batch_size = 1 << 24);
};