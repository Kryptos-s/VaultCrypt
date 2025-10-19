#include "vaultcrypt/keystore.h"
#include "vaultcrypt/error.h"
#include "vaultcrypt/logger.h"
#include "vaultcrypt/aead.h"
#include "vaultcrypt/file_io.h"
#include <nlohmann/json.hpp>
#include <chrono>
#include <map>
#include <sstream>
#include <iomanip>  // ADD THIS