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

inline constexpr uint32_t kBlocklistProductionKeyId = 2173599637u;
inline constexpr uint32_t kBlocklistAcceptedListId = 1u;

struct TrustedBlocklistKey {
  uint32_t keyId;
  uint8_t sec1PublicKey[kBlocklistSec1PublicKeySize];
};

inline constexpr TrustedBlocklistKey kTrustedBlocklistKeys[] = {{
    kBlocklistProductionKeyId,
    {
        0x04, 0xC6, 0x42, 0xB5, 0x00, 0xA5, 0x37, 0x8C, 0xD0, 0xA4, 0xFD,
        0xD3, 0xFC, 0x10, 0x28, 0xFB, 0xF3, 0xE3, 0xE9, 0x08, 0xBD, 0x7F,
        0x7A, 0x85, 0x54, 0x85, 0xC9, 0x74, 0x73, 0x05, 0x05, 0x71, 0x76,
        0x2E, 0xAE, 0xD9, 0x35, 0x00, 0x8E, 0x0A, 0x4F, 0x32, 0xEB, 0x0F,
        0xA6, 0x6B, 0x51, 0xD4, 0x3E, 0x3F, 0x8F, 0x84, 0x9F, 0xFA, 0x32,
        0x99, 0x35, 0x5A, 0x32, 0xC3, 0x94, 0x33, 0xBE, 0xC7, 0x65,
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
static_assert(kBlocklistProductionKeyId == 2173599637u);
static_assert(kBlocklistAcceptedListId == 1u);
static_assert(kTrustedBlocklistKeyCount == 1);
static_assert(sizeof(kTrustedBlocklistKeys[0].sec1PublicKey) == 65);
static_assert(kTrustedBlocklistKeys[0].sec1PublicKey[0] == 0x04);
static_assert(trustedBlocklistKeyIdsAreUnique());
