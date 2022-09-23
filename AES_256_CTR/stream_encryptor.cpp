#include "stream_encryptor.h"
#include "AES_256_ctr.h"

void stream_encryptor::encrypt(std::shared_ptr<const encryption_settings> i_settings, int i_batch_size)
{
	std::vector<uint8_t> result(i_batch_size, 0);
	std::optional<int64_t> nonce = std::nullopt;
	auto& istr = i_settings->istr;
	auto& ostr = i_settings->ostr;
	auto& e_mode = i_settings->m_mode;
	if (e_mode == encryption_mode::e_decrypt)
	{
		int64_t n;
		istr.read(reinterpret_cast<char*>(&n), sizeof(n));
		nonce = decltype(nonce)(n);
		if (const int bytes_read = static_cast<int>(istr.gcount()); bytes_read != sizeof(n))
			throw std::invalid_argument("The file is corrupted for decryption. Cannot read nonce.");
	}

	AES_256_ctr aes(i_settings->m_key, nonce);
	if (e_mode == encryption_mode::e_encrypt)
	{
		int64_t n = aes.get_nonce();
		ostr.write(reinterpret_cast<char*>(&n), sizeof(n));
	}

	for (;;)
	{
		if (istr.eof())
			break;
		istr.read(reinterpret_cast<char*>(result.data()), i_batch_size);
		const int bytes_read = static_cast<int>(istr.gcount());
		if (bytes_read)
		{
			e_mode == encryption_mode::e_encrypt ? aes.encrypt(result) : aes.decrypt(result);
			ostr.write(reinterpret_cast<char*>(result.data()), bytes_read);
		}
	}
}