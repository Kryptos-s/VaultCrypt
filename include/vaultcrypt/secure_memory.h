#pragma once

#include <cstddef>
#include <cstring>
#include <memory>
#include <vector>
#include <string>

namespace vaultcrypt {

    // Secure zero memory
    void secure_zero(void* ptr, size_t len);

    // Constant-time comparison
    bool constant_time_compare(const void* a, const void* b, size_t len);

    // Secure allocator with memory locking and zeroing
    template<typename T>
    class SecureAllocator {
    public:
        using value_type = T;

        SecureAllocator() = default;
        template<typename U>
        SecureAllocator(const SecureAllocator<U>&) noexcept {}

        T* allocate(size_t n);
        void deallocate(T* ptr, size_t n) noexcept;
    };

    template<typename T>
    using SecureVector = std::vector<T, SecureAllocator<T>>;

    using SecureBytes = SecureVector<unsigned char>;
    using SecureString = std::basic_string<char, std::char_traits<char>, SecureAllocator<char>>;

} // namespace vaultcrypt