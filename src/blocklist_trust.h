#pragma once

#include <stddef.h>
#include <stdint.h>

inline constexpr uint8_t kBlocklistManifestMagic[] = {'N', 'S', 'B', 'M'};
inline constexpr uint8_t kBlocklistSignatureDomain[] = {
    'N', 'S', 'M', '-', 'B', 'L', 'O', 'C',
    'K', 'L', 'I', 'S', 'T', '-', 'V', '1',
};

inline constexpr uint8_t kBlocklistManifestVersion = 1;
inline constexpr uint8_t kBlocklistFormatVersion = 1;
inline constexpr uint8_t kBlocklistSignatureAlgorithm = 1;
inline constexpr uint8_t kBlocklistManifestFlags = 0;

inline constexpr size_t kBlocklistSec1PublicKeySize = 65;
inline constexpr size_t kBlocklistManifestSize = 64;
inline constexpr size_t kBlocklistSignatureSize = 64;
inline constexpr size_t kBlocklistProofSize = 128;
inline constexpr size_t kBlocklistProofHexSize = 256;

inline constexpr size_t kBlocklistMagicOffset = 0;
inline constexpr size_t kBlocklistManifestVersionOffset = 4;
inline constexpr size_t kBlocklistFormatVersionOffset = 5;
inline constexpr size_t kBlocklistAlgorithmOffset = 6;
inline constexpr size_t kBlocklistFlagsOffset = 7;
inline constexpr size_t kBlocklistKeyIdOffset = 8;
inline constexpr size_t kBlocklistListIdOffset = 12;
inline constexpr size_t kBlocklistSequenceOffset = 16;
inline constexpr size_t kBlocklistPayloadSizeOffset = 24;
inline constexpr size_t kBlocklistRecordCountOffset = 28;
inline constexpr size_t kBlocklistPayloadSha256Offset = 32;
inline constexpr size_t kBlocklistSignatureROffset = 64;
inline constexpr size_t kBlocklistSignatureSOffset = 96;

inline constexpr uint32_t kBlocklistProductionKeyId = 2008216462u;
inline constexpr uint32_t kBlocklistAcceptedListId = 1u;

struct TrustedBlocklistKey {
  uint32_t keyId;
  uint8_t sec1PublicKey[kBlocklistSec1PublicKeySize];
};

inline constexpr TrustedBlocklistKey kTrustedBlocklistKeys[] = {{
    kBlocklistProductionKeyId,
    {
        0x04, 0x39, 0x04, 0x70, 0xC8, 0x44, 0xA8, 0xE7, 0x25, 0xD7, 0x9C,
        0xF2, 0x39, 0x3A, 0xE8, 0x71, 0xC0, 0x0B, 0x4A, 0xE5, 0x68, 0x15,
        0xEB, 0x86, 0xA6, 0xF0, 0x3B, 0x73, 0x05, 0x2C, 0xEB, 0x74, 0x36,
        0x6B, 0xD2, 0xDF, 0x61, 0x12, 0x28, 0xB5, 0xB5, 0x63, 0xE5, 0xA2,
        0x7F, 0x90, 0xD7, 0xFE, 0x77, 0xCD, 0x4B, 0x66, 0x1B, 0x03, 0xBC,
        0x4C, 0xCE, 0xC3, 0xB0, 0xC6, 0x98, 0x70, 0x4A, 0x82, 0x59,
    },
}};

inline constexpr size_t kTrustedBlocklistKeyCount =
    sizeof(kTrustedBlocklistKeys) / sizeof(kTrustedBlocklistKeys[0]);

inline constexpr const TrustedBlocklistKey* findTrustedBlocklistKey(
    uint32_t keyId) {
  for (const TrustedBlocklistKey& key : kTrustedBlocklistKeys) {
    if (key.keyId == keyId) return &key;
  }
  return nullptr;
}

inline constexpr bool trustedBlocklistKeyIdsAreUnique() {
  for (size_t left = 0; left < kTrustedBlocklistKeyCount; ++left) {
    for (size_t right = left + 1; right < kTrustedBlocklistKeyCount; ++right) {
      if (kTrustedBlocklistKeys[left].keyId ==
          kTrustedBlocklistKeys[right].keyId) {
        return false;
      }
    }
  }
  return true;
}

static_assert(sizeof(kBlocklistManifestMagic) == 4);
static_assert(sizeof(kBlocklistSignatureDomain) == 16);
static_assert(kBlocklistPayloadSha256Offset + 32 == kBlocklistManifestSize);
static_assert(kBlocklistSignatureROffset == kBlocklistManifestSize);
static_assert(kBlocklistSignatureSOffset ==
              kBlocklistManifestSize + kBlocklistSignatureSize / 2);
static_assert(kBlocklistSignatureSOffset + kBlocklistSignatureSize / 2 ==
              kBlocklistProofSize);
static_assert(kBlocklistProofHexSize == kBlocklistProofSize * 2);
static_assert(kBlocklistProductionKeyId == 2008216462u);
static_assert(kBlocklistAcceptedListId == 1u);
static_assert(kTrustedBlocklistKeyCount == 1);
static_assert(sizeof(kTrustedBlocklistKeys[0].sec1PublicKey) == 65);
static_assert(kTrustedBlocklistKeys[0].sec1PublicKey[0] == 0x04);
static_assert(trustedBlocklistKeyIdsAreUnique());
