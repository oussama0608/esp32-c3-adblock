#include "dns_protocol.h"

#include <string.h>

namespace dns_protocol {
namespace {

constexpr uint16_t FLAG_QR = 0x8000;
constexpr uint16_t FLAG_OPCODE = 0x7800;
constexpr uint16_t FLAG_TC = 0x0200;
constexpr uint16_t FLAG_RD = 0x0100;
constexpr uint16_t FLAG_RA = 0x0080;
constexpr uint16_t FLAG_Z_RESERVED = 0x0040;
constexpr uint16_t FLAG_AD = 0x0020;
constexpr uint16_t FLAG_CD = 0x0010;
constexpr uint16_t QUERY_ALLOWED_FLAGS = FLAG_RD | FLAG_AD | FLAG_CD;
constexpr size_t DNS_RR_FIXED_BYTES = 10;
constexpr size_t DNS_RR_MIN_BYTES = 11;
constexpr uint16_t DNS_COMPRESSION_POINTER_MAX = 32;

uint16_t readU16(const uint8_t* data) {
  return static_cast<uint16_t>((static_cast<uint16_t>(data[0]) << 8) |
                               static_cast<uint16_t>(data[1]));
}

void writeU16(uint8_t* data, uint16_t value) {
  data[0] = static_cast<uint8_t>(value >> 8);
  data[1] = static_cast<uint8_t>(value & 0xFF);
}

uint8_t asciiLower(uint8_t value) {
  if (value >= static_cast<uint8_t>('A') &&
      value <= static_cast<uint8_t>('Z')) {
    return static_cast<uint8_t>(value + ('a' - 'A'));
  }
  return value;
}

enum class NameStatus : uint8_t {
  OK,
  TRUNCATED,
  COMPRESSED,
  RESERVED_LABEL,
  TOO_LONG,
};

NameStatus parseClientName(const uint8_t* packet, size_t packetLength,
                           size_t* offset, QueryInfo* info) {
  const size_t nameStart = *offset;
  size_t presentationLength = 0;
  uint16_t labelCount = 0;

  while (true) {
    if (*offset >= packetLength) return NameStatus::TRUNCATED;

    const uint8_t labelLength = packet[(*offset)++];
    const uint8_t labelType = labelLength & 0xC0;
    if (labelType == 0xC0) return NameStatus::COMPRESSED;
    if (labelType != 0) return NameStatus::RESERVED_LABEL;

    const size_t wireLength = *offset - nameStart;
    if (wireLength > DNS_QNAME_WIRE_MAX_BYTES) return NameStatus::TOO_LONG;
    if (labelLength == 0) break;

    if (labelCount >= 127) return NameStatus::TOO_LONG;
    if (static_cast<size_t>(labelLength) > packetLength - *offset) {
      return NameStatus::TRUNCATED;
    }

    const size_t separatorBytes = labelCount == 0 ? 0 : 1;
    if (presentationLength + separatorBytes + labelLength >
        DNS_PRESENTATION_NAME_MAX_BYTES) {
      return NameStatus::TOO_LONG;
    }

    if (separatorBytes != 0) {
      info->blocklistName[presentationLength++] = '.';
    }
    for (uint8_t i = 0; i < labelLength; ++i) {
      info->blocklistName[presentationLength++] =
          static_cast<char>(asciiLower(packet[(*offset)++]));
    }
    ++labelCount;

    if (*offset - nameStart > DNS_QNAME_WIRE_MAX_BYTES) {
      return NameStatus::TOO_LONG;
    }
  }

  info->blocklistName[presentationLength] = '\0';
  info->presentationLength = static_cast<uint16_t>(presentationLength);
  info->blocklistNameLength = static_cast<uint16_t>(presentationLength);
  info->qnameWireLength = static_cast<uint16_t>(*offset - nameStart);
  info->labelCount = static_cast<uint8_t>(labelCount);
  info->root = labelCount == 0;

  if (presentationLength > 4 &&
      memcmp(info->blocklistName, "www.", 4) == 0) {
    const size_t strippedLength = presentationLength - 4;
    memmove(info->blocklistName, info->blocklistName + 4,
            strippedLength);
    info->blocklistName[strippedLength] = '\0';
    info->blocklistNameLength = static_cast<uint16_t>(strippedLength);
  }
  return NameStatus::OK;
}

ResponseStatus compareResponseQuestion(
    const uint8_t* originalQuery, size_t originalQueryLength,
    const QueryInfo& query, const uint8_t* response, size_t responseLength,
    size_t* responseQuestionEnd) {
  size_t queryOffset = DNS_HEADER_BYTES;
  size_t responseOffset = DNS_HEADER_BYTES;
  size_t responsePresentationLength = 0;
  size_t responseWireLength = 0;
  uint16_t responseLabelCount = 0;

  while (true) {
    if (queryOffset >= originalQueryLength || responseOffset >= responseLength) {
      return ResponseStatus::MALFORMED_QUESTION;
    }

    const uint8_t queryLabelLength = originalQuery[queryOffset++];
    const uint8_t responseLabelLength = response[responseOffset++];
    const uint8_t responseLabelType = responseLabelLength & 0xC0;
    if (responseLabelType == 0xC0) {
      return ResponseStatus::COMPRESSED_QUESTION;
    }
    if (responseLabelType != 0) {
      return ResponseStatus::MALFORMED_QUESTION;
    }

    ++responseWireLength;
    if (responseWireLength > DNS_QNAME_WIRE_MAX_BYTES) {
      return ResponseStatus::MALFORMED_QUESTION;
    }
    if (queryLabelLength != responseLabelLength) {
      return ResponseStatus::NAME_MISMATCH;
    }
    if (responseLabelLength == 0) break;

    if (responseLabelCount >= 127) {
      return ResponseStatus::MALFORMED_QUESTION;
    }
    if (static_cast<size_t>(responseLabelLength) >
            responseLength - responseOffset ||
        static_cast<size_t>(queryLabelLength) >
            originalQueryLength - queryOffset) {
      return ResponseStatus::MALFORMED_QUESTION;
    }

    const size_t separatorBytes = responseLabelCount == 0 ? 0 : 1;
    if (responsePresentationLength + separatorBytes + responseLabelLength >
        DNS_PRESENTATION_NAME_MAX_BYTES) {
      return ResponseStatus::MALFORMED_QUESTION;
    }
    responsePresentationLength += separatorBytes + responseLabelLength;
    responseWireLength += responseLabelLength;
    if (responseWireLength > DNS_QNAME_WIRE_MAX_BYTES) {
      return ResponseStatus::MALFORMED_QUESTION;
    }

    for (uint8_t i = 0; i < responseLabelLength; ++i) {
      if (asciiLower(originalQuery[queryOffset++]) !=
          asciiLower(response[responseOffset++])) {
        return ResponseStatus::NAME_MISMATCH;
      }
    }
    ++responseLabelCount;
  }

  if (responseLabelCount != query.labelCount ||
      responseWireLength != query.qnameWireLength) {
    return ResponseStatus::NAME_MISMATCH;
  }
  if (responseOffset + 4 > responseLength ||
      queryOffset + 4 > originalQueryLength) {
    return ResponseStatus::MALFORMED_QUESTION;
  }

  const uint16_t responseType = readU16(response + responseOffset);
  responseOffset += 2;
  const uint16_t responseClass = readU16(response + responseOffset);
  responseOffset += 2;
  if (responseType != query.qtype) return ResponseStatus::TYPE_MISMATCH;
  if (responseClass != query.qclass) return ResponseStatus::CLASS_MISMATCH;

  *responseQuestionEnd = responseOffset;
  return ResponseStatus::VALID;
}

bool skipCompressedName(const uint8_t* packet, size_t packetLength,
                        size_t nameOffset, size_t* consumedBytes) {
  size_t cursor = nameOffset;
  size_t consumed = 0;
  size_t expandedWireLength = 0;
  size_t presentationLength = 0;
  uint16_t labelCount = 0;
  uint16_t pointerCount = 0;
  bool followingPointer = false;

  while (true) {
    if (cursor >= packetLength) return false;
    const uint8_t length = packet[cursor];
    const uint8_t labelType = length & 0xC0;

    if (labelType == 0xC0) {
      if (cursor + 1 >= packetLength) return false;
      const size_t target =
          (static_cast<size_t>(length & 0x3F) << 8) | packet[cursor + 1];
      // Backward-only pointers are the deliberately narrow V1 policy. They
      // guarantee termination without allocating a visited-offset table.
      if (target < DNS_HEADER_BYTES || target >= cursor) return false;
      if (!followingPointer) consumed += 2;
      cursor = target;
      followingPointer = true;
      if (++pointerCount > DNS_COMPRESSION_POINTER_MAX) return false;
      continue;
    }
    if (labelType != 0) return false;

    if (!followingPointer) ++consumed;
    ++cursor;
    ++expandedWireLength;
    if (expandedWireLength > DNS_QNAME_WIRE_MAX_BYTES) return false;
    if (length == 0) {
      *consumedBytes = consumed;
      return true;
    }

    if (labelCount >= 127) return false;
    if (static_cast<size_t>(length) > packetLength - cursor) return false;
    const size_t separatorBytes = labelCount == 0 ? 0 : 1;
    if (presentationLength + separatorBytes + length >
        DNS_PRESENTATION_NAME_MAX_BYTES) {
      return false;
    }
    presentationLength += separatorBytes + length;
    expandedWireLength += length;
    if (expandedWireLength > DNS_QNAME_WIRE_MAX_BYTES) return false;
    if (!followingPointer) consumed += length;
    cursor += length;
    ++labelCount;
  }
}

bool validateDeclaredRecords(const uint8_t* packet, size_t packetLength,
                             size_t offset, uint16_t answerCount,
                             uint16_t authorityCount,
                             uint16_t additionalCount) {
  const uint32_t recordCount = static_cast<uint32_t>(answerCount) +
                               static_cast<uint32_t>(authorityCount) +
                               static_cast<uint32_t>(additionalCount);
  if (offset > packetLength) return false;
  if (recordCount > (packetLength - offset) / DNS_RR_MIN_BYTES) return false;

  for (uint32_t record = 0; record < recordCount; ++record) {
    size_t ownerBytes = 0;
    if (!skipCompressedName(packet, packetLength, offset, &ownerBytes)) {
      return false;
    }
    if (ownerBytes > packetLength - offset) return false;
    offset += ownerBytes;
    if (DNS_RR_FIXED_BYTES > packetLength - offset) return false;
    const uint16_t rdLength = readU16(packet + offset + 8);
    offset += DNS_RR_FIXED_BYTES;
    if (rdLength > packetLength - offset) return false;
    offset += rdLength;
  }
  return offset == packetLength;
}

uint16_t responseFlags(const uint8_t* query, ResponseCode code) {
  const uint16_t queryFlags = readU16(query + 2);
  return static_cast<uint16_t>(
      FLAG_QR | FLAG_RA |
      (queryFlags & (FLAG_OPCODE | FLAG_RD | FLAG_AD | FLAG_CD)) |
      static_cast<uint8_t>(code));
}

void clearResponseCounts(uint8_t* output, uint16_t questionCount,
                         uint16_t answerCount) {
  writeU16(output + 4, questionCount);
  writeU16(output + 6, answerCount);
  writeU16(output + 8, 0);
  writeU16(output + 10, 0);
}

}  // namespace

QueryStatus parseClientQuery(const uint8_t* packet, size_t packetLength,
                             QueryInfo* info) {
  if (info == nullptr) return QueryStatus::DROP;
  memset(info, 0, sizeof(*info));
  if (packet == nullptr || packetLength < DNS_HEADER_BYTES ||
      packetLength > DNS_PACKET_MAX_BYTES) {
    return QueryStatus::DROP;
  }

  info->clientId = readU16(packet);
  const uint16_t flags = readU16(packet + 2);
  info->opcode = static_cast<uint8_t>((flags & FLAG_OPCODE) >> 11);

  if ((flags & FLAG_QR) != 0) return QueryStatus::DROP;
  if (info->opcode != 0) return QueryStatus::NOTIMP;
  if ((flags & FLAG_TC) != 0) return QueryStatus::FORMERR;
  // A client query may request recursion and carry AD/CD. Response-only AA,
  // RA/RCODE and the reserved Z bit are rejected.
  if ((flags & ~QUERY_ALLOWED_FLAGS) != 0) return QueryStatus::FORMERR;

  const uint16_t questionCount = readU16(packet + 4);
  const uint16_t answerCount = readU16(packet + 6);
  const uint16_t authorityCount = readU16(packet + 8);
  const uint16_t additionalCount = readU16(packet + 10);
  if (questionCount != 1 || answerCount != 0 || authorityCount != 0 ||
      additionalCount > 1) {
    return QueryStatus::FORMERR;
  }

  size_t offset = DNS_HEADER_BYTES;
  const NameStatus nameStatus =
      parseClientName(packet, packetLength, &offset, info);
  if (nameStatus == NameStatus::COMPRESSED) return QueryStatus::NOTIMP;
  if (nameStatus != NameStatus::OK) return QueryStatus::FORMERR;
  if (offset + 4 > packetLength) return QueryStatus::FORMERR;

  info->qtype = readU16(packet + offset);
  info->qclass = readU16(packet + offset + 2);
  offset += 4;
  info->questionEnd = static_cast<uint16_t>(offset);
  if (info->qtype == 0) return QueryStatus::FORMERR;
  if (info->qclass != DNS_CLASS_IN) return QueryStatus::REFUSED;

  if (additionalCount == 0) {
    return offset == packetLength ? QueryStatus::VALID : QueryStatus::FORMERR;
  }

  // The only accepted additional record is one complete EDNS0 OPT RR.
  if (offset >= packetLength || packet[offset] != 0) {
    return QueryStatus::FORMERR;
  }
  ++offset;
  if (DNS_RR_FIXED_BYTES > packetLength - offset) {
    return QueryStatus::FORMERR;
  }
  if (readU16(packet + offset) != DNS_TYPE_OPT) {
    return QueryStatus::FORMERR;
  }
  // OPT TTL layout: extended RCODE, version, then 16 flag bits.
  if (packet[offset + 5] != 0) return QueryStatus::FORMERR;
  const uint16_t rdLength = readU16(packet + offset + 8);
  offset += DNS_RR_FIXED_BYTES;
  if (rdLength > packetLength - offset) return QueryStatus::FORMERR;
  offset += rdLength;
  return offset == packetLength ? QueryStatus::VALID : QueryStatus::FORMERR;
}

ResponseStatus validateUpstreamResponse(
    const uint8_t* originalQuery, size_t originalQueryLength,
    const QueryInfo& query, const uint8_t* response, size_t responseLength,
    uint16_t upstreamTransactionId) {
  if (response == nullptr || responseLength < DNS_HEADER_BYTES) {
    return ResponseStatus::TOO_SHORT;
  }
  if (responseLength > DNS_PACKET_MAX_BYTES) {
    return ResponseStatus::TOO_LARGE;
  }
  if (originalQuery == nullptr || originalQueryLength < query.questionEnd ||
      query.questionEnd < DNS_HEADER_BYTES) {
    return ResponseStatus::MALFORMED_QUESTION;
  }
  if (readU16(response) != upstreamTransactionId) {
    return ResponseStatus::WRONG_ID;
  }

  const uint16_t flags = readU16(response + 2);
  if ((flags & FLAG_QR) == 0) return ResponseStatus::NOT_RESPONSE;
  if (static_cast<uint8_t>((flags & FLAG_OPCODE) >> 11) != query.opcode) {
    return ResponseStatus::WRONG_OPCODE;
  }
  if ((flags & FLAG_Z_RESERVED) != 0) {
    return ResponseStatus::BAD_RESERVED_FLAGS;
  }
  if (readU16(response + 4) != 1) {
    return ResponseStatus::WRONG_QUESTION_COUNT;
  }

  size_t responseQuestionEnd = 0;
  const ResponseStatus questionStatus = compareResponseQuestion(
      originalQuery, originalQueryLength, query, response, responseLength,
      &responseQuestionEnd);
  if (questionStatus != ResponseStatus::VALID) return questionStatus;

  // A fully correlated TC response is forwarded so the client receives the
  // protocol's explicit truncation signal. NetShield does not implement TCP/53.
  if ((flags & FLAG_TC) != 0) return ResponseStatus::VALID;

  return validateDeclaredRecords(
             response, responseLength, responseQuestionEnd,
             readU16(response + 6), readU16(response + 8),
             readU16(response + 10))
             ? ResponseStatus::VALID
             : ResponseStatus::MALFORMED_SECTIONS;
}

bool endpointMatches(const Ipv4Endpoint& actual,
                     const Ipv4Endpoint& expected) {
  return actual.port == expected.port &&
         memcmp(actual.address, expected.address, sizeof(actual.address)) == 0;
}

bool setTransactionId(uint8_t* packet, size_t packetLength,
                      uint16_t transactionId) {
  if (packet == nullptr || packetLength < 2) return false;
  writeU16(packet, transactionId);
  return true;
}

ResponseCode responseCodeFor(QueryStatus status) {
  switch (status) {
    case QueryStatus::FORMERR:
      return ResponseCode::FORMAT_ERROR;
    case QueryStatus::NOTIMP:
      return ResponseCode::NOT_IMPLEMENTED;
    case QueryStatus::REFUSED:
      return ResponseCode::REFUSED;
    case QueryStatus::VALID:
    case QueryStatus::DROP:
      return ResponseCode::NO_ERROR;
  }
  return ResponseCode::SERVER_FAILURE;
}

size_t buildErrorResponse(const uint8_t* query, size_t queryLength,
                          const QueryInfo* question, ResponseCode code,
                          uint8_t* output, size_t outputCapacity) {
  if (query == nullptr || output == nullptr || queryLength < DNS_HEADER_BYTES ||
      outputCapacity < DNS_HEADER_BYTES) {
    return 0;
  }

  size_t responseLength = DNS_HEADER_BYTES;
  if (question != nullptr && question->questionEnd >= DNS_HEADER_BYTES &&
      question->questionEnd <= queryLength &&
      question->questionEnd <= outputCapacity) {
    responseLength = question->questionEnd;
  }
  memmove(output, query, responseLength);
  writeU16(output + 2, responseFlags(query, code));
  clearResponseCounts(output, responseLength > DNS_HEADER_BYTES ? 1 : 0, 0);
  return responseLength;
}

size_t buildBlockedResponse(const uint8_t* query, size_t queryLength,
                            const QueryInfo& question, uint8_t* output,
                            size_t outputCapacity) {
  if (query == nullptr || output == nullptr ||
      question.questionEnd < DNS_HEADER_BYTES ||
      question.questionEnd > queryLength ||
      question.questionEnd > outputCapacity) {
    return 0;
  }

  constexpr uint8_t BLOCKED_A_ANSWER[] = {
      0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
      0x01, 0x2C, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
  };
  const bool answerA = question.qtype == DNS_TYPE_A;
  const size_t answerLength = answerA ? sizeof(BLOCKED_A_ANSWER) : 0;
  if (answerLength > outputCapacity - question.questionEnd) return 0;

  memmove(output, query, question.questionEnd);
  writeU16(output + 2, responseFlags(query, ResponseCode::NO_ERROR));
  clearResponseCounts(output, 1, answerA ? 1 : 0);
  if (answerA) {
    memcpy(output + question.questionEnd, BLOCKED_A_ANSWER, answerLength);
  }
  return question.questionEnd + answerLength;
}

}  // namespace dns_protocol
