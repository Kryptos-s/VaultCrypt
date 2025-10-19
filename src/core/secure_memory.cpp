#include "vaultcrypt/secure_memory.h"
#include "vaultcrypt/error.h"
#include <algorithm>
#include <limits>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace vaultcrypt {

    void secure_zero(void* ptr, size_t len) {
        if (!ptr || len == 0) return;

#ifdef _WIN32
        SecureZeroMemory(ptr, len);
#else
        volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
        while (len--) *p++ = 0;
#endif
    }

    bool constant_time_compare(const void* a, const void* b, size_t len) {
        const unsigned char* aa = static_cast<const unsigned char*>(a);
        const unsigned char* bb = static_cast<const unsigned char*>(b);
        unsigned char result = 0;

        for (size_t i = 0; i < len; ++i) {
            result |= aa[i] ^ bb[i];
        }

        return result == 0;
    }

    template<typename T>
    T* SecureAllocator<T>::allocate(size_t n) {
        if (n > std::numeric_limits<size_t>::max() / sizeof(T)) {
            throw VaultCryptException(ErrorCode::MemoryError, "Allocation size overflow");
        }

        size_t bytes = n * sizeof(T);

#ifdef _WIN32
        void* ptr = VirtualAlloc(nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!ptr) {
            throw VaultCryptException(ErrorCode::MemoryError, "VirtualAlloc failed");
        }
        VirtualLock(ptr, bytes);
#else
        void* ptr = mmap(nullptr, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ptr == MAP_FAILED) {
            throw VaultCryptException(ErrorCode::MemoryError, "mmap failed");
        }
        mlock(ptr, bytes);
#endif

        return static_cast<T*>(ptr);
    }

    template<typename T>
    void SecureAllocator<T>::deallocate(T* ptr, size_t n) noexcept {
        if (!ptr) return;

        size_t bytes = n * sizeof(T);
        secure_zero(ptr, bytes);

#ifdef _WIN32
        VirtualUnlock(ptr, bytes);
        VirtualFree(ptr, 0, MEM_RELEASE);
#else
        munlock(ptr, bytes);
        munmap(ptr, bytes);
#endif
    }

    // EXPLICIT INSTANTIATIONS - ADD ALL OF THESE
    template class SecureAllocator<unsigned char>;
    template class SecureAllocator<char>;

    // STL internal types that need instantiation
    template class SecureAllocator<std::_Container_proxy>;

    // Instantiate for common types used in vectors
    template SecureAllocator<unsigned char>::SecureAllocator() noexcept;
    template SecureAllocator<char>::SecureAllocator() noexcept;

} // namespace vaultcrypt