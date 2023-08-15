// Compound file binary format
// Based on the definition at:
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cfb/

#pragma MIME application/zlib
#pragma endian little

#include <std/core.pat>
#include <std/sys.pat>

using BitfieldOrder = std::core::BitfieldOrder;

#define MAGIC_HEADER 0xe11ab1a1e011cfd0
#define VERSION3 0x03
#define VERSION4 0x04

struct Cfb {
    // Magic number
    u64 header_signature;
    // Class GUID (unused)
    u128 clsid;
    // Schema version
    u16 minor_version;
    // Schema minor version
    u16 major_version;
    // LE/BE order (always LE)
    u16 byte_order;
    // Sector size as a power of 2
    u16 sector_shift;
    // Mini stream sector size
    u16 minisec_shift;
    // Blank reserved bits
    u16 reserved0;
    u32 reserved1;
    // Number of directory sectors
    u32 dir_sec_count;
    // Number of FAT sectors
    u32 fat_sec_count;
    // First directory sector
    u32 dir_sec_start;
    // Transaction number, if counted
    u32 txn_signature_number;
    // Maximum size for a mini stream
    u32 mini_stream_cutoff_size;
    // First MiniFAT sector
    u32 minifat_sec_start;
    // Number of MiniFAT sectors
    u32 minifat_sec_count;
    // First DIFAT sector
    u32 difat_sec_start;
    // Number of DIFAT sectors
    u32 difat_sec_count;
    // Locations of the first 109 FAT sectors
    u32 difat[109];
    
    // v4 sectors are 4096 bytes, the header is zero-padded
    if (major_version == VERSION4) {
        u8 v4_header_padding[3584];
    }
};


// start parsing at the beginning of stream
Cfb cfb @ 0x00;

// header  valiation
std::assert_warn(
    cfb.header_signature == MAGIC_HEADER,
    "Invalid header signature"
);

std::assert_warn(cfb.clsid == 0x0, "Invalid CLSID");

std::assert_warn(
    cfb.minor_version == 0x3e,
    "Unrecognized minor version"
);

std::assert(
    cfb.major_version == VERSION3 || cfb.major_version == VERSION4,
    "Unrecognized major version"
);

std::assert_warn(
    cfb.reserved0 == 0x0 && cfb.reserved1 == 0x0,
    "Invalid reserved bits"
);


std::assert_warn(
    cfb.minisec_shift == 0x0006,
    "Unrecognized major version"
);

std::assert_warn(
    cfb.mini_stream_cutoff_size == 0x00001000,
    "Unrecognized major version"
);
