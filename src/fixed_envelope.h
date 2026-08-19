#pragma once

#include <stddef.h>
#include <stdint.h>

namespace fixed_envelope {

enum class ReceiveStatus : uint8_t {
  OK,
  END_OF_BODY,
  TIMEOUT,
  ERROR,
  DEADLINE,
};

struct ReceiveResult {
  ReceiveStatus status;
  size_t length;
};

using ReceiveFunction = ReceiveResult (*)(void* context, char* buffer, size_t length);
using ClockFunction = uint32_t (*)();

inline bool deadlineReached(uint32_t now, uint32_t started, uint32_t duration) {
  return static_cast<uint32_t>(now - started) >= duration;
}

class Reader {
 public:
  Reader(size_t totalLength, uint32_t started, uint32_t deadlineMs,
         void* context, ReceiveFunction receive, ClockFunction clock)
      : remaining_(totalLength), started_(started), deadlineMs_(deadlineMs),
        context_(context), receive_(receive), clock_(clock) {}

  ReceiveStatus readExact(uint8_t* output, size_t outputLength) {
    if (!output && outputLength) return ReceiveStatus::ERROR;
    for (size_t index = 0; index < outputLength; ++index) {
      uint8_t value = 0;
      const ReceiveStatus status = next(&value);
      if (status != ReceiveStatus::OK) return status;
      output[index] = value;
    }
    return ReceiveStatus::OK;
  }

  ReceiveStatus next(uint8_t* output) {
    if (!output || !remaining_) return ReceiveStatus::END_OF_BODY;
    if (!clock_ || deadlineReached(clock_(), started_, deadlineMs_)) {
      return ReceiveStatus::DEADLINE;
    }
    if (offset_ == available_) {
      if (!receive_) return ReceiveStatus::ERROR;
      const size_t wanted = remaining_ < sizeof(buffer_) ? remaining_ : sizeof(buffer_);
      const ReceiveResult result = receive_(context_, buffer_, wanted);
      if (result.status != ReceiveStatus::OK || result.length == 0 || result.length > wanted) {
        return result.status == ReceiveStatus::OK ? ReceiveStatus::ERROR : result.status;
      }
      offset_ = 0;
      available_ = result.length;
    }
    *output = static_cast<uint8_t>(buffer_[offset_++]);
    --remaining_;
    return ReceiveStatus::OK;
  }

  size_t remaining() const { return remaining_; }

 private:
  size_t remaining_;
  size_t offset_ = 0;
  size_t available_ = 0;
  uint32_t started_;
  uint32_t deadlineMs_;
  void* context_;
  ReceiveFunction receive_;
  ClockFunction clock_;
  char buffer_[512];
};

inline bool hasExactPayloadLength(size_t totalLength, size_t proofLength,
                                  size_t authenticatedPayloadLength) {
  return totalLength > proofLength && authenticatedPayloadLength == totalLength - proofLength;
}

inline bool hasAllowedPayloadLength(size_t totalLength, size_t proofLength,
                                    size_t authenticatedPayloadLength,
                                    size_t maximumPayloadLength) {
  return authenticatedPayloadLength > 0 &&
         authenticatedPayloadLength <= maximumPayloadLength &&
         hasExactPayloadLength(totalLength, proofLength, authenticatedPayloadLength);
}

}  // namespace fixed_envelope
