#ifndef CORE_FEX_SRC_GUESTIMAGE_HPP
#define CORE_FEX_SRC_GUESTIMAGE_HPP

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace Aps5Fex {

struct GuestTlsTemplate {
    std::uint64_t address = 0;
    std::size_t fileSize = 0;
    std::size_t memorySize = 0;
    std::size_t alignment = 1;
};

// What a symbol stands for: the address of a function or variable, or for a TLS variable its module,
// its offset in that module's TLS block, and how far below the thread pointer that block lies.
struct GuestSymbol {
    std::uint64_t address = 0;
    bool tls = false;
    std::uint64_t tlsModule = 0;
    std::uint64_t tlsValue = 0;
    std::uint64_t tlsOffset = 0;
};

// A relinked x86-64 executable or guest module (the relinker's Linux output) mapped into this
// process. Guest code is never host executable: FEXCore reads it and runs its own translation.
class GuestImage {
public:
    // Resolves an imported symbol, or gives nothing for one that no image or library defines.
    using Resolver = std::function<std::optional<GuestSymbol>(const std::string& name, bool weak)>;

    explicit GuestImage(const std::filesystem::path& path);
    GuestImage(const GuestImage&) = delete;
    GuestImage& operator=(const GuestImage&) = delete;
    ~GuestImage();

    const std::filesystem::path& Path() const { return path; }
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

    // The image's TLS module number and how far below the thread pointer its TLS block lies.
    void SetTls(std::uint64_t module, std::uint64_t offset) {
        tlsModule = module;
        tlsOffset = offset;
    }

    // A symbol the image exports.
    std::optional<GuestSymbol> Export(const std::string& name) const;

    void Relocate(const Resolver& resolve);

    // The functions to run before the program starts, in order: DT_INIT, then DT_INIT_ARRAY. Valid
    // after Relocate.
    std::vector<std::uint64_t> Initializers() const;

private:
    struct Exported {
        std::uint64_t value;
        bool tls;
    };

    std::filesystem::path path;
    std::uint64_t base = 0;
    std::uint64_t start = 0;
    std::size_t size = 0;
    std::uint64_t entry = 0;
    std::uint64_t dynamic = 0;
    std::vector<std::string> needed;
    std::vector<unsigned char> programHeaders;
    std::unordered_map<std::string, Exported> exports;
    GuestTlsTemplate tls;
    std::uint64_t tlsModule = 0;
    std::uint64_t tlsOffset = 0;
};

}

#endif
