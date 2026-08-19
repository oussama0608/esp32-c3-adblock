#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "fixed_envelope.h"

static int failures = 0;
#define CHECK(x) do { if (!(x)) { std::printf("failed: %s\n", #x); ++failures; } } while (0)

struct FakeReceive {
  std::vector<uint8_t> bytes;
  std::vector<size_t> chunks;
  size_t offset = 0;
  size_t chunkIndex = 0;
  fixed_envelope::ReceiveStatus terminal = fixed_envelope::ReceiveStatus::END_OF_BODY;
};

static uint32_t fakeNow = 0;

static uint32_t fakeClock() { return fakeNow; }

static fixed_envelope::ReceiveResult receive(void* context, char* output, size_t wanted) {
  auto* source = static_cast<FakeReceive*>(context);
  if (source->offset == source->bytes.size()) return {source->terminal, 0};
  const size_t configured = source->chunkIndex < source->chunks.size()
      ? source->chunks[source->chunkIndex++] : source->bytes.size() - source->offset;
  const size_t available = source->bytes.size() - source->offset;
  const size_t count = configured < available ? configured : available;
  if (count == 0 || count > wanted) return {fixed_envelope::ReceiveStatus::ERROR, 0};
  memcpy(output, source->bytes.data() + source->offset, count);
  source->offset += count;
  return {fixed_envelope::ReceiveStatus::OK, count};
}

static std::vector<uint8_t> envelope(size_t payloadLength) {
  std::vector<uint8_t> result(128 + payloadLength);
  for (size_t index = 0; index < result.size(); ++index) {
    result[index] = static_cast<uint8_t>(index);
  }
  return result;
}

int main() {
  using fixed_envelope::ReceiveStatus;

  for (size_t split = 1; split < 128; ++split) {
    FakeReceive source{envelope(3), {split, 131 - split}};
    std::array<uint8_t, 128> proof{};
    fixed_envelope::Reader reader(source.bytes.size(), 0, 30000, &source, receive, fakeClock);
    CHECK(reader.readExact(proof.data(), proof.size()) == ReceiveStatus::OK);
    CHECK(proof[0] == 0 && proof[127] == 127);
    std::array<uint8_t, 3> payload{};
    CHECK(reader.readExact(payload.data(), payload.size()) == ReceiveStatus::OK);
    CHECK(payload[0] == 128 && payload[2] == 130 && reader.remaining() == 0);
  }

  FakeReceive prefetched{envelope(4), {132}};
  std::array<uint8_t, 128> proof{};
  std::array<uint8_t, 4> payload{};
  fixed_envelope::Reader prefetchedReader(prefetched.bytes.size(), 0, 30000,
                                          &prefetched, receive, fakeClock);
  CHECK(prefetchedReader.readExact(proof.data(), proof.size()) == ReceiveStatus::OK);
  CHECK(prefetchedReader.readExact(payload.data(), payload.size()) == ReceiveStatus::OK);
  CHECK(payload[0] == 128 && payload[3] == 131 && prefetchedReader.remaining() == 0);

  CHECK(!fixed_envelope::hasExactPayloadLength(128, 128, 0));
  CHECK(!fixed_envelope::hasExactPayloadLength(133, 128, 4));
  CHECK(!fixed_envelope::hasExactPayloadLength(260, 128, 4));
  CHECK(fixed_envelope::hasExactPayloadLength(132, 128, 4));
  CHECK(fixed_envelope::hasAllowedPayloadLength(128 + 524285, 128, 524285, 524285));
  CHECK(!fixed_envelope::hasAllowedPayloadLength(128 + 524286, 128, 524286, 524285));
  CHECK(!fixed_envelope::hasAllowedPayloadLength(128, 128, 0, 524285));
  CHECK(!fixed_envelope::hasAllowedPayloadLength(133, 128, 4, 524285));  // trailing byte

  FakeReceive truncated{envelope(3), {127}};
  truncated.bytes.resize(127);
  fixed_envelope::Reader truncatedReader(131, 0, 30000, &truncated, receive, fakeClock);
  CHECK(truncatedReader.readExact(proof.data(), proof.size()) == ReceiveStatus::END_OF_BODY);

  FakeReceive payloadTruncated{envelope(3), {130}};
  payloadTruncated.bytes.resize(130);
  fixed_envelope::Reader payloadTruncatedReader(131, 0, 30000,
                                                 &payloadTruncated, receive, fakeClock);
  CHECK(payloadTruncatedReader.readExact(proof.data(), proof.size()) == ReceiveStatus::OK);
  CHECK(payloadTruncatedReader.readExact(payload.data(), 3) == ReceiveStatus::END_OF_BODY);

  FakeReceive timeout;
  timeout.terminal = ReceiveStatus::TIMEOUT;
  fixed_envelope::Reader timeoutReader(128, 0, 30000, &timeout, receive, fakeClock);
  CHECK(timeoutReader.readExact(proof.data(), proof.size()) == ReceiveStatus::TIMEOUT);

  FakeReceive socketError;
  socketError.terminal = ReceiveStatus::ERROR;
  fixed_envelope::Reader errorReader(128, 0, 30000, &socketError, receive, fakeClock);
  CHECK(errorReader.readExact(proof.data(), proof.size()) == ReceiveStatus::ERROR);

  fakeNow = 30000;
  FakeReceive late{envelope(1), {129}};
  fixed_envelope::Reader lateReader(late.bytes.size(), 0, 30000, &late, receive, fakeClock);
  CHECK(lateReader.readExact(proof.data(), proof.size()) == ReceiveStatus::DEADLINE);
  fakeNow = 0;

  return failures ? 1 : 0;
}
