#pragma once
#include "encryption_key_base.h"

#include <vector>
#include <optional>
#include <memory>

class AES_256_ctr final
{
public:
	explicit AES_256_ctr(std::shared_ptr<encryption_key_base const> i_key, std::optional<int64_t> i_nonce = std::nullopt);
	AES_256_ctr() = delete;
	AES_256_ctr(const AES_256_ctr&) = delete;
	AES_256_ctr(AES_256_ctr&&) = delete;
	~AES_256_ctr() = default;
	int64_t get_nonce() const;
	void encrypt(std::vector<uint8_t>& io_data);
	void decrypt(std::vector<uint8_t>& io_data);
private:
	const std::shared_ptr<encryption_key_base const> m_key;
	uint64_t m_processed_blocks;
	const int64_t m_nonce;
};