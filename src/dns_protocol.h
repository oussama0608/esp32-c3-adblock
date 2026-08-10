#ifndef NETSHIELD_MINI_DNS_PROTOCOL_H
#define NETSHIELD_MINI_DNS_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

namespace dns_protocol {

constexpr size_t DNS_PACKET_MAX_BYTES = 600;
constexpr uint32_t DNS_UPSTREAM_TIMEOUT_MS = 1000;
constexpr uint8_t DNS_STALE_DRAIN_MAX = 8;
constexpr uint8_t DNS_RESPONSE_CANDIDATE_MAX = 8;

constexpr size_t DNS_HEADER_BYTES = 12;
constexpr size_t DNS_QNAME_WIRE_MAX_BYTES = 255;
constexpr size_t DNS_PRESENTATION_NAME_MAX_BYTES = 253;
constexpr uint16_t DNS_CLASS_IN = 1;
constexpr uint16_t DNS_TYPE_A = 1;
constexpr uint16_t DNS_TYPE_AAAA = 28;
constexpr uint16_t DNS_TYPE_OPT = 41;

enum class QueryStatus : uint8_t {
  VALID,
  DROP,
  FORMERR,
  NOTIMP,
  REFUSED,
};

enum class ResponseStatus : uint8_t {
  VALID,
  TOO_SHORT,
  TOO_LARGE,
  WRONG_ID,
  NOT_RESPONSE,
  WRONG_OPCODE,
  BAD_RESERVED_FLAGS,
  WRONG_QUESTION_COUNT,
  MALFORMED_QUESTION,
  COMPRESSED_QUESTION,
  NAME_MISMATCH,
  TYPE_MISMATCH,
  CLASS_MISMATCH,
  MALFORMED_SECTIONS,
};

enum class ResponseCode : uint8_t {
  NO_ERROR = 0,
  FORMAT_ERROR = 1,
  SERVER_FAILURE = 2,
  NOT_IMPLEMENTED = 4,
  REFUSED = 5,
};

struct QueryInfo {
  uint16_t clientId;
  uint16_t qtype;
  uint16_t qclass;
  uint16_t questionEnd;
  uint16_t qnameWireLength;
  uint16_t presentationLength;
  uint16_t blocklistNameLength;
  uint8_t opcode;
  uint8_t labelCount;
  bool root;
  // ASCII case-folded name used only for blocklist matching. A leading
  // "www." is removed here, never from the wire question used for correlation.
  char blocklistName[DNS_PRESENTATION_NAME_MAX_BYTES + 1];
};

struct Ipv4Endpoint {
  uint8_t address[4];
  uint16_t port;
};

QueryStatus parseClientQuery(const uint8_t* packet, size_t packetLength,
                             QueryInfo* info);

ResponseStatus validateUpstreamResponse(
    const uint8_t* originalQuery, size_t originalQueryLength,
    const QueryInfo& query, const uint8_t* response, size_t responseLength,
    uint16_t upstreamTransactionId);

bool endpointMatches(const Ipv4Endpoint& actual,
                     const Ipv4Endpoint& expected);

bool setTransactionId(uint8_t* packet, size_t packetLength,
                      uint16_t transactionId);

ResponseCode responseCodeFor(QueryStatus status);

// Builds a header-only error unless `question` describes a complete, validated
// question. The output may alias the query buffer.
size_t buildErrorResponse(const uint8_t* query, size_t queryLength,
                          const QueryInfo* question, ResponseCode code,
                          uint8_t* output, size_t outputCapacity);

// Preserves the original question and client ID. A blocked A query gets an
// IN/A 0.0.0.0 answer; every other QTYPE gets NOERROR/NODATA.
size_t buildBlockedResponse(const uint8_t* query, size_t queryLength,
                            const QueryInfo& question, uint8_t* output,
                            size_t outputCapacity);

}  // namespace dns_protocol

#endif  // NETSHIELD_MINI_DNS_PROTOCOL_H
