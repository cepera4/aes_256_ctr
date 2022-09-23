#include "encryption_key.h"

#include "encryption_settings.h"
#include "stream_encryptor.h"

#include <iostream>
#include <fstream>
#include <filesystem>

void try_parse_and_process(char** argv)
{
	namespace fs = std::filesystem;
	fs::path p_in(argv[0]);
	if (!fs::exists(p_in))
		throw std::invalid_argument(("File <" + p_in.string() + "> doesn't exist.").c_str());
	fs::path p_out(argv[1]);

	std::ifstream ifs(argv[0], std::ios::binary | std::ios_base::in);
	std::ofstream ofs(argv[1], std::ios::binary | std::ios_base::out);

	if (!ifs.good())
		throw std::invalid_argument(("File <" + p_in.string() + "> cannot be opened. Check if it's corrupted.").c_str());
	if (!ofs.good())
		throw std::invalid_argument(("File <" + p_out.string() + "> cannot be created. Check if the path is correct.").c_str());

	std::shared_ptr<encryption_key_base> key;
	try
	{
		key = std::make_shared<encryption_key<256>>(std::string(argv[2]));
	}
	catch (const std::exception& e)
	{
		throw(e);
	}

	encryption_mode e_mode;

	if (const auto enc = std::string(argv[3]); enc == "encrypt" || enc == "decrypt")
		e_mode = (enc == "encrypt") ? encryption_mode::e_encrypt : encryption_mode::e_decrypt;
	else
		throw std::invalid_argument("Invalid encryption argument: must be \"encrypt\" or \"decrypt\"");

	std::cout
		<< "Starting " << (e_mode == encryption_mode::e_encrypt ? "encryption." : "decryption.") << std::endl
		<< "input: " << p_in.string() << std::endl;

	try
	{
		stream_encryptor::encrypt(std::make_shared<encryption_settings>(encryption_settings{ ifs, ofs, key, e_mode }));
	}
	catch (const std::exception& e)
	{
		throw(e);
	}

	std::cout
		<< "Finished." << std::endl
		<< "output: " << p_out.string() << std::endl
		<< "_________________________________________________________" << std::endl;
}

std::string help()
{
	return std::string() +
		"==============================================================================================================\n" +
		"Pass 4 parameters {<input_path>, <output_path>, <key>, <encryption_mode>} per each encryption/decryption task.\n" +
		"<input_path>      = path to existing file for encryption/decryption\n" +
		"<output_path>     = path to resulting file\n" +
		"<key>             = hexadecimal 256 bit key\n" +
		"<encryption_mode> = \"encrypt\"/\"decrypt\" for encryption/decryption\n" +
		"==============================================================================================================\n";
}

int main(int argc, char** argv)
{
	try
	{
		const int num_args = argc - 1;
		if (num_args < 4 || num_args % 4)
			throw std::invalid_argument("Number of arguments should be divisible by 4.");
		for (int i = 0; i < num_args; i += 4)
			try_parse_and_process(argv + 1 + i);
	}
	catch (const std::exception& e)
	{
		std::cerr << "ERROR!!!" << std::endl << e.what() << std::endl;
		std::cout << help();
		return -1;
	}

	return 0;
}