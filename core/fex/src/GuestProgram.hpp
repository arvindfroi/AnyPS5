#ifndef CORE_FEX_SRC_GUESTPROGRAM_HPP
#define CORE_FEX_SRC_GUESTPROGRAM_HPP

#include "GuestImage.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <utility>
#include <vector>

namespace Aps5Fex {

class Bridge;

// The static TLS of a guest thread: each image's TLS template at its offset below the thread pointer.
struct GuestTlsLayout {
    struct Block {
        std::uint64_t templateAddress;
        std::size_t fileSize;
        std::uint64_t offset;
    };

    std::vector<Block> blocks;
    // The lowest the blocks reach below the thread pointer, and the alignment the thread pointer needs.
    std::uint64_t size = 0;
    std::size_t alignment = 16;
};

// A relinked executable and the guest modules it needs, loaded, laid out and relocated as the
// dynamic linker would: the modules named by $ORIGIN paths in DT_NEEDED, and the HLE libraries for
// the other names. Imports named NID#guest come from the modules.
class GuestProgram {
public:
    GuestProgram(const std::filesystem::path& executable, Bridge& bridge);

    const GuestImage& Executable() const { return *images.front(); }
    const std::vector<std::unique_ptr<GuestImage>>& Images() const { return images; }
    // The modules' initializers, dependencies first.
    std::vector<std::uint64_t> Initializers() const;
    const GuestTlsLayout& Tls() const { return tls; }
    // Where guest code is: [start, end) of each image.
    std::vector<std::pair<std::uint64_t, std::uint64_t>> CodeRanges() const;

private:
    void Load(const std::filesystem::path& path, Bridge& bridge);

    std::vector<std::unique_ptr<GuestImage>> images;
    GuestTlsLayout tls;
};

}

#endif
