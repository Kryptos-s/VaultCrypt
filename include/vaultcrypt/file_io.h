#pragma once

#include "secure_memory.h"
#include <string>
#include <fstream>

namespace vaultcrypt {

	// Read entire file into secure memory
	SecureBytes read_file(const std::string& path);

	// Write secure data to file
	void write_file(const std::string& path, const SecureBytes& data, bool overwrite = false);

	// Secure file deletion (overwrite then delete)
	void secure_delete_file(const std::string& path);

} // namespace vaultcrypt