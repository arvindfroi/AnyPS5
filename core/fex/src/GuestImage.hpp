#ifndef CORE_FEX_SRC_GUESTIMAGE_HPP
#define CORE_FEX_SRC_GUESTIMAGE_HPP

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

namespace Aps5Fex {

struct GuestTlsTemplate {
    std::uint64_t address = 0;
    std::size_t fileSize = 0;
    std::size_t memorySize = 0;
    std::size_t alignment = 1;
};

// A relinked x86-64 executable (the relinker's Linux output) mapped into this process. Guest code
// is never host executable: FEXCore reads it and runs its own translation.
class GuestImage {
public:
    // Resolves an imported symbol name to its address, or 0 when it has none.
    using Resolver = std::function<std::uint64_t(const std::string& name, bool weak)>;

    explicit GuestImage(const std::filesystem::path& path);
    GuestImage(const GuestImage&) = delete;
    GuestImage& operator=(const GuestImage&) = delete;
    ~GuestImage();

    std::uint64_t Base() const { return base; }
    std::uint64_t Start() const { return start; }
    std::size_t Size() const { return size; }
    std::uint64_t Entry() const { return entry; }
    const std::vector<std::string>& Needed() const { return needed; }
    const GuestTlsTemplate& Tls() const { return tls; }
    // The ELF program headers, for dl_iterate_phdr.
    const void* ProgramHeaders() const { return programHeaders.data(); }
    std::size_t ProgramHeaderCount() const { return programHeaders.size() / ProgramHeaderSize; }

    static constexpr std::size_t ProgramHeaderSize = 56;

    void Relocate(const Resolver& resolve);

private:
    std::uint64_t base = 0;
    std::uint64_t start = 0;
    std::size_t size = 0;
    std::uint64_t entry = 0;
    std::uint64_t dynamic = 0;
    std::vector<std::string> needed;
    std::vector<unsigned char> programHeaders;
    GuestTlsTemplate tls;
};

}

#endif
