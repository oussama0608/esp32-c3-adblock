#include "dns_protocol.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

namespace dp = dns_protocol;

namespace {

int failures = 0;
uint64_t checks = 0;

void check(bool condition, const char* expression, const char* file, int line) {
  ++checks;
  if (!condition) {
    std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
    ++failures;
  }
}

#define CHECK(condition) check((condition), #condition, __FILE__, __LINE__)

void writeU16(std::vector<uint8_t>* packet, size_t offset, uint16_t value) {
  (*packet)[offset] = static_cast<uint8_t>(value >> 8);
  (*packet)[offset + 1] = static_cast<uint8_t>(value & 0xFF);
}

uint16_t readU16(const std::vector<uint8_t>& packet, size_t offset) {
  return static_cast<uint16_t>(
      (static_cast<uint16_t>(packet[offset]) << 8) | packet[offset + 1]);
}

std::vector<std::string> splitName(const std::string& name) {
  std::vector<std::string> labels;
  if (name.empty()) return labels;
  size_t start = 0;
  while (true) {
    const size_t dot = name.find('.', start);
    labels.push_back(name.substr(start, dot == std::string::npos
                                           ? std::string::npos
                                           : dot - start));
    if (dot == std::string::npos) break;
    start = dot + 1;
  }
  return labels;
}

void appendName(std::vector<uint8_t>* packet,
                const std::vector<std::string>& labels) {
  for (const std::string& label : labels) {
    packet->push_back(static_cast<uint8_t>(label.size()));
    packet->insert(packet->end(), label.begin(), label.end());
  }
  packet->push_back(0);
}

std::vector<uint8_t> makeQuery(
    const std::vector<std::string>& labels, uint16_t qtype = dp::DNS_TYPE_A,
    uint16_t qclass = dp::DNS_CLASS_IN, uint16_t flags = 0x0100,
    const std::vector<uint8_t>* ednsOptions = nullptr) {
  std::vector<uint8_t> packet(dp::DNS_HEADER_BYTES, 0);
  writeU16(&packet, 0, 0x1234);
  writeU16(&packet, 2, flags);
  writeU16(&packet, 4, 1);
  writeU16(&packet, 10, ednsOptions == nullptr ? 0 : 1);
  appendName(&packet, labels);
  packet.push_back(static_cast<uint8_t>(qtype >> 8));
  packet.push_back(static_cast<uint8_t>(qtype));
  packet.push_back(static_cast<uint8_t>(qclass >> 8));
  packet.push_back(static_cast<uint8_t>(qclass));

  if (ednsOptions != nullptr) {
    packet.push_back(0);                 // root owner
    packet.push_back(0);                 // TYPE OPT
    packet.push_back(dp::DNS_TYPE_OPT);
    packet.push_back(0x04);              // UDP size 1232, preserved as-is
    packet.push_back(0xD0);
    packet.insert(packet.end(), 4, 0);   // ext RCODE, version 0, flags
    packet.push_back(static_cast<uint8_t>(ednsOptions->size() >> 8));
    packet.push_back(static_cast<uint8_t>(ednsOptions->size()));
    packet.insert(packet.end(), ednsOptions->begin(), ednsOptions->end());
  }
  return packet;
}

std::vector<uint8_t> makeQuery(
    const std::string& name, uint16_t qtype = dp::DNS_TYPE_A,
    uint16_t qclass = dp::DNS_CLASS_IN, uint16_t flags = 0x0100,
    const std::vector<uint8_t>* ednsOptions = nullptr) {
  return makeQuery(splitName(name), qtype, qclass, flags, ednsOptions);
}

dp::QueryInfo parseValid(const std::vector<uint8_t>& query) {
  dp::QueryInfo info{};
  CHECK(dp::parseClientQuery(query.data(), query.size(), &info) ==
        dp::QueryStatus::VALID);
  return info;
}

std::vector<uint8_t> makeResponse(const std::vector<uint8_t>& query,
                                  const dp::QueryInfo& info,
                                  uint16_t upstreamId = 0xBEEF,
                                  uint16_t flags = 0x8180) {
  std::vector<uint8_t> response(query.begin(), query.begin() + info.questionEnd);
  writeU16(&response, 0, upstreamId);
  writeU16(&response, 2, flags);
  writeU16(&response, 4, 1);
  writeU16(&response, 6, 0);
  writeU16(&response, 8, 0);
  writeU16(&response, 10, 0);
  return response;
}

void uppercaseQuestionName(std::vector<uint8_t>* packet) {
  size_t offset = dp::DNS_HEADER_BYTES;
  while (offset < packet->size()) {
    const uint8_t length = (*packet)[offset++];
    if (length == 0) return;
    for (uint8_t i = 0; i < length && offset < packet->size(); ++i, ++offset) {
      uint8_t& value = (*packet)[offset];
      if (value >= 'a' && value <= 'z') value -= static_cast<uint8_t>('a' - 'A');
    }
  }
}

void appendARecord(std::vector<uint8_t>* response) {
  writeU16(response, 6, 1);
  const uint8_t record[] = {
      0xC0, 0x0C,              // owner -> original question
      0x00, 0x01,              // A
      0x00, 0x01,              // IN
      0x00, 0x00, 0x00, 0x3C,  // TTL
      0x00, 0x04,              // RDLENGTH
      192, 0, 2, 1,
  };
  response->insert(response->end(), record, record + sizeof(record));
}

void testConstantsAndEndpoints() {
  CHECK(dp::DNS_PACKET_MAX_BYTES == 600);
  CHECK(dp::DNS_UPSTREAM_TIMEOUT_MS == 1000);
  CHECK(dp::DNS_STALE_DRAIN_MAX == 8);
  CHECK(dp::DNS_RESPONSE_CANDIDATE_MAX == 8);

  const dp::Ipv4Endpoint quad9{{9, 9, 9, 9}, 53};
  const dp::Ipv4Endpoint same{{9, 9, 9, 9}, 53};
  const dp::Ipv4Endpoint wrongIp{{9, 9, 9, 10}, 53};
  const dp::Ipv4Endpoint wrongPort{{9, 9, 9, 9}, 5353};
  CHECK(dp::endpointMatches(same, quad9));
  CHECK(!dp::endpointMatches(wrongIp, quad9));
  CHECK(!dp::endpointMatches(wrongPort, quad9));
}

void testParserBoundaries() {
  {
    const std::vector<uint8_t> query = makeQuery("");
    dp::QueryInfo info = parseValid(query);
    CHECK(info.root);
    CHECK(info.labelCount == 0);
    CHECK(info.presentationLength == 0);
    CHECK(info.blocklistNameLength == 0);
  }
  {
    const std::vector<uint8_t> query = makeQuery("Example.COM");
    const dp::QueryInfo info = parseValid(query);
    CHECK(!info.root);
    CHECK(info.qtype == dp::DNS_TYPE_A);
    CHECK(std::string(info.blocklistName) == "example.com");
  }
  {
    const std::vector<uint8_t> query =
        makeQuery("WWW.Example.COM", dp::DNS_TYPE_AAAA);
    const dp::QueryInfo info = parseValid(query);
    CHECK(info.qtype == dp::DNS_TYPE_AAAA);
    CHECK(std::string(info.blocklistName) == "example.com");
    CHECK(info.presentationLength == 15);
    CHECK(info.blocklistNameLength == 11);
  }
  {
    const std::vector<uint8_t> query =
        makeQuery(std::vector<std::string>{std::string(63, 'a')});
    const dp::QueryInfo info = parseValid(query);
    CHECK(info.presentationLength == 63);
  }
  {
    std::vector<uint8_t> query(dp::DNS_HEADER_BYTES, 0);
    writeU16(&query, 4, 1);
    query.push_back(64);
    query.insert(query.end(), 64, 'a');
    query.push_back(0);
    query.insert(query.end(), {0, 1, 0, 1});
    dp::QueryInfo info{};
    CHECK(dp::parseClientQuery(query.data(), query.size(), &info) ==
          dp::QueryStatus::FORMERR);
  }
  {
    std::vector<std::string> labels(127, "a");
    const std::vector<uint8_t> query = makeQuery(labels);
    dp::QueryInfo info = parseValid(query);
    CHECK(info.labelCount == 127);
    CHECK(info.presentationLength == 253);
    CHECK(info.qnameWireLength == 255);

    labels[0] = "aa";
    const std::vector<uint8_t> tooLong = makeQuery(labels);
    CHECK(dp::parseClientQuery(tooLong.data(), tooLong.size(), &info) ==
          dp::QueryStatus::FORMERR);
  }

  for (size_t length = 0; length <= 16; ++length) {
    const std::vector<uint8_t> packet(length, 0);
    dp::QueryInfo info{};
    const dp::QueryStatus status =
        dp::parseClientQuery(packet.data(), packet.size(), &info);
    CHECK(status == (length < dp::DNS_HEADER_BYTES ? dp::QueryStatus::DROP
                                                   : dp::QueryStatus::FORMERR));
  }

  {
    std::vector<uint8_t> truncated(dp::DNS_HEADER_BYTES, 0);
    writeU16(&truncated, 4, 1);
    truncated.insert(truncated.end(), {3, 'a', 'b'});
    dp::QueryInfo info{};
    CHECK(dp::parseClientQuery(truncated.data(), truncated.size(), &info) ==
          dp::QueryStatus::FORMERR);
  }
  {
    std::vector<uint8_t> noRoot(dp::DNS_HEADER_BYTES, 0);
    writeU16(&noRoot, 4, 1);
    noRoot.insert(noRoot.end(), {3, 'a', 'b', 'c', 1, 'x', 1, 'y'});
    dp::QueryInfo info{};
    CHECK(dp::parseClientQuery(noRoot.data(), noRoot.size(), &info) ==
          dp::QueryStatus::FORMERR);
  }
  for (const uint8_t reserved : {static_cast<uint8_t>(0x40),
                                 static_cast<uint8_t>(0x80)}) {
    std::vector<uint8_t> query(dp::DNS_HEADER_BYTES, 0);
    writeU16(&query, 4, 1);
    query.insert(query.end(), {reserved, 0, 0, 1, 0, 1});
    dp::QueryInfo info{};
    CHECK(dp::parseClientQuery(query.data(), query.size(), &info) ==
          dp::QueryStatus::FORMERR);
  }
  {
    std::vector<uint8_t> query(dp::DNS_HEADER_BYTES, 0);
    writeU16(&query, 4, 1);
    query.insert(query.end(), {0xC0, 0x0C, 0, 1, 0, 1});
    dp::QueryInfo info{};
    CHECK(dp::parseClientQuery(query.data(), query.size(), &info) ==
          dp::QueryStatus::NOTIMP);
  }
}

void testParserHeaderAndEdnsPolicy() {
  const std::vector<uint8_t> base = makeQuery("example.com");
  dp::QueryInfo info{};

  const uint16_t questionCounts[] = {0, 1, 2};
  for (const uint16_t qdCount : questionCounts) {
    std::vector<uint8_t> query = base;
    writeU16(&query, 4, qdCount);
    const dp::QueryStatus expected =
        qdCount == 1 ? dp::QueryStatus::VALID : dp::QueryStatus::FORMERR;
    CHECK(dp::parseClientQuery(query.data(), query.size(), &info) == expected);
  }
  for (const size_t countOffset : {static_cast<size_t>(6),
                                   static_cast<size_t>(8)}) {
    std::vector<uint8_t> query = base;
    writeU16(&query, countOffset, 1);
    CHECK(dp::parseClientQuery(query.data(), query.size(), &info) ==
          dp::QueryStatus::FORMERR);
  }
  {
    std::vector<uint8_t> query = base;
    writeU16(&query, 10, 2);
    CHECK(dp::parseClientQuery(query.data(), query.size(), &info) ==
          dp::QueryStatus::FORMERR);
  }
  {
    std::vector<uint8_t> query = base;
    writeU16(&query, 2, 0x8100);
    CHECK(dp::parseClientQuery(query.data(), query.size(), &info) ==
          dp::QueryStatus::DROP);
  }
  {
    std::vector<uint8_t> query = base;
    writeU16(&query, 2, 0x0900);
    CHECK(dp::parseClientQuery(query.data(), query.size(), &info) ==
          dp::QueryStatus::NOTIMP);
  }
  for (const uint16_t flags : {static_cast<uint16_t>(0x0300),
                               static_cast<uint16_t>(0x0140),
                               static_cast<uint16_t>(0x0180),
                               static_cast<uint16_t>(0x0101)}) {
    std::vector<uint8_t> query = base;
    writeU16(&query, 2, flags);
    CHECK(dp::parseClientQuery(query.data(), query.size(), &info) ==
          dp::QueryStatus::FORMERR);
  }
  {
    const std::vector<uint8_t> query =
        makeQuery("example.com", 0, dp::DNS_CLASS_IN);
    CHECK(dp::parseClientQuery(query.data(), query.size(), &info) ==
          dp::QueryStatus::FORMERR);
  }
  {
    const std::vector<uint8_t> query = makeQuery("example.com", 1, 3);
    CHECK(dp::parseClientQuery(query.data(), query.size(), &info) ==
          dp::QueryStatus::REFUSED);
    CHECK(info.questionEnd != 0);
  }
  {
    std::vector<uint8_t> query = base;
    query.push_back(0xA5);
    CHECK(dp::parseClientQuery(query.data(), query.size(), &info) ==
          dp::QueryStatus::FORMERR);
  }
  {
    std::vector<uint8_t> wrongAdditional = base;
    writeU16(&wrongAdditional, 10, 1);
    wrongAdditional.insert(wrongAdditional.end(), {
        0,                    // root owner
        0, 1,                // TYPE A, not OPT
        0x04, 0xD0,          // CLASS / advertised size
        0, 0, 0, 0,          // TTL
        0, 0,                // RDLENGTH
    });
    CHECK(dp::parseClientQuery(wrongAdditional.data(), wrongAdditional.size(),
                               &info) == dp::QueryStatus::FORMERR);
  }

  const std::vector<uint8_t> options = {0x00, 0x0A, 0x00, 0x00};
  const std::vector<uint8_t> edns =
      makeQuery("example.com", dp::DNS_TYPE_A, dp::DNS_CLASS_IN, 0x0130,
                &options);
  const dp::QueryInfo ednsInfo = parseValid(edns);
  CHECK(ednsInfo.questionEnd < edns.size());

  {
    std::vector<uint8_t> truncated = edns;
    truncated.pop_back();
    CHECK(dp::parseClientQuery(truncated.data(), truncated.size(), &info) ==
          dp::QueryStatus::FORMERR);
  }
  {
    std::vector<uint8_t> wrongVersion = edns;
    wrongVersion[ednsInfo.questionEnd + 6] = 1;
    CHECK(dp::parseClientQuery(wrongVersion.data(), wrongVersion.size(), &info) ==
          dp::QueryStatus::FORMERR);
  }
  {
    std::vector<uint8_t> wrongOwner = edns;
    wrongOwner[ednsInfo.questionEnd] = 1;
    CHECK(dp::parseClientQuery(wrongOwner.data(), wrongOwner.size(), &info) ==
          dp::QueryStatus::FORMERR);
  }

  const std::vector<uint8_t> noOptions;
  const std::vector<uint8_t> ednsBase =
      makeQuery("a", dp::DNS_TYPE_A, dp::DNS_CLASS_IN, 0x0100, &noOptions);
  CHECK(ednsBase.size() < dp::DNS_PACKET_MAX_BYTES);
  const size_t optionLength = dp::DNS_PACKET_MAX_BYTES - ednsBase.size();
  const std::vector<uint8_t> boundaryOptions(optionLength, 0x5A);
  const std::vector<uint8_t> boundary =
      makeQuery("a", dp::DNS_TYPE_A, dp::DNS_CLASS_IN, 0x0100,
                &boundaryOptions);
  CHECK(boundary.size() == dp::DNS_PACKET_MAX_BYTES);
  CHECK(dp::parseClientQuery(boundary.data(), boundary.size(), &info) ==
        dp::QueryStatus::VALID);

  std::vector<uint8_t> oversized = boundary;
  oversized.push_back(0);
  CHECK(dp::parseClientQuery(oversized.data(), oversized.size(), &info) ==
        dp::QueryStatus::DROP);
}

void testResponseCorrelation() {
  const std::vector<uint8_t> query = makeQuery("www.Example.com");
  const dp::QueryInfo info = parseValid(query);
  const uint16_t upstreamId = 0xBEEF;
  const std::vector<uint8_t> valid = makeResponse(query, info, upstreamId);

  const std::vector<uint8_t> immutableQuery = query;
  const std::vector<uint8_t> immutableResponse = valid;
  CHECK(dp::validateUpstreamResponse(query.data(), query.size(), info,
                                     valid.data(), valid.size(), upstreamId) ==
        dp::ResponseStatus::VALID);
  CHECK(query == immutableQuery);
  CHECK(valid == immutableResponse);

  {
    std::vector<uint8_t> response = valid;
    writeU16(&response, 0, 0xCAFE);
    CHECK(dp::validateUpstreamResponse(query.data(), query.size(), info,
                                       response.data(), response.size(),
                                       upstreamId) ==
          dp::ResponseStatus::WRONG_ID);
  }
  {
    std::vector<uint8_t> response = valid;
    response[13] = 'z';
    CHECK(dp::validateUpstreamResponse(query.data(), query.size(), info,
                                       response.data(), response.size(),
                                       upstreamId) ==
          dp::ResponseStatus::NAME_MISMATCH);
  }
  {
    std::vector<uint8_t> response = valid;
    response[info.questionEnd - 4] = 0;
    response[info.questionEnd - 3] = dp::DNS_TYPE_AAAA;
    CHECK(dp::validateUpstreamResponse(query.data(), query.size(), info,
                                       response.data(), response.size(),
                                       upstreamId) ==
          dp::ResponseStatus::TYPE_MISMATCH);
  }
  {
    std::vector<uint8_t> response = valid;
    response[info.questionEnd - 1] = 3;
    CHECK(dp::validateUpstreamResponse(query.data(), query.size(), info,
                                       response.data(), response.size(),
                                       upstreamId) ==
          dp::ResponseStatus::CLASS_MISMATCH);
  }
  {
    std::vector<uint8_t> response = valid;
    writeU16(&response, 2, 0x0180);
    CHECK(dp::validateUpstreamResponse(query.data(), query.size(), info,
                                       response.data(), response.size(),
                                       upstreamId) ==
          dp::ResponseStatus::NOT_RESPONSE);
  }
  {
    std::vector<uint8_t> response = valid;
    writeU16(&response, 2, 0x8980);
    CHECK(dp::validateUpstreamResponse(query.data(), query.size(), info,
                                       response.data(), response.size(),
                                       upstreamId) ==
          dp::ResponseStatus::WRONG_OPCODE);
  }
  {
    std::vector<uint8_t> response = valid;
    writeU16(&response, 2, 0x81C0);
    CHECK(dp::validateUpstreamResponse(query.data(), query.size(), info,
                                       response.data(), response.size(),
                                       upstreamId) ==
          dp::ResponseStatus::BAD_RESERVED_FLAGS);
  }
  {
    std::vector<uint8_t> response = valid;
    writeU16(&response, 4, 2);
    CHECK(dp::validateUpstreamResponse(query.data(), query.size(), info,
                                       response.data(), response.size(),
                                       upstreamId) ==
          dp::ResponseStatus::WRONG_QUESTION_COUNT);
  }
  {
    std::vector<uint8_t> compressed(dp::DNS_HEADER_BYTES, 0);
    writeU16(&compressed, 0, upstreamId);
    writeU16(&compressed, 2, 0x8180);
    writeU16(&compressed, 4, 1);
    compressed.insert(compressed.end(), {0xC0, 0x0C, 0, 1, 0, 1});
    CHECK(dp::validateUpstreamResponse(query.data(), query.size(), info,
                                       compressed.data(), compressed.size(),
                                       upstreamId) ==
          dp::ResponseStatus::COMPRESSED_QUESTION);
  }
  for (const uint8_t reserved : {static_cast<uint8_t>(0x40),
                                 static_cast<uint8_t>(0x80)}) {
    std::vector<uint8_t> response(dp::DNS_HEADER_BYTES, 0);
    writeU16(&response, 0, upstreamId);
    writeU16(&response, 2, 0x8180);
    writeU16(&response, 4, 1);
    response.insert(response.end(), {reserved, 0, 0, 1, 0, 1});
    CHECK(dp::validateUpstreamResponse(query.data(), query.size(), info,
                                       response.data(), response.size(),
                                       upstreamId) ==
          dp::ResponseStatus::MALFORMED_QUESTION);
  }
  {
    std::vector<uint8_t> response = valid;
    uppercaseQuestionName(&response);
    CHECK(dp::validateUpstreamResponse(query.data(), query.size(), info,
                                       response.data(), response.size(),
                                       upstreamId) ==
          dp::ResponseStatus::VALID);
  }
  for (size_t length = 0; length < dp::DNS_HEADER_BYTES; ++length) {
    CHECK(dp::validateUpstreamResponse(query.data(), query.size(), info,
                                       valid.data(), length, upstreamId) ==
          dp::ResponseStatus::TOO_SHORT);
  }
  {
    std::vector<uint8_t> oversized(dp::DNS_PACKET_MAX_BYTES + 1, 0);
    CHECK(dp::validateUpstreamResponse(query.data(), query.size(), info,
                                       oversized.data(), oversized.size(),
                                       upstreamId) ==
          dp::ResponseStatus::TOO_LARGE);
  }
  {
    std::vector<uint8_t> tc = valid;
    writeU16(&tc, 2, static_cast<uint16_t>(readU16(tc, 2) | 0x0200));
    writeU16(&tc, 6, 1);
    tc.push_back(0xC0);  // a correlated TC reply may end mid-record
    CHECK(dp::validateUpstreamResponse(query.data(), query.size(), info,
                                       tc.data(), tc.size(), upstreamId) ==
          dp::ResponseStatus::VALID);
  }
  {
    std::vector<uint8_t> complete = valid;
    appendARecord(&complete);
    CHECK(dp::validateUpstreamResponse(query.data(), query.size(), info,
                                       complete.data(), complete.size(),
                                       upstreamId) ==
          dp::ResponseStatus::VALID);

    std::vector<uint8_t> truncated = complete;
    truncated.pop_back();
    CHECK(dp::validateUpstreamResponse(query.data(), query.size(), info,
                                       truncated.data(), truncated.size(),
                                       upstreamId) ==
          dp::ResponseStatus::MALFORMED_SECTIONS);
  }
  {
    std::vector<uint8_t> missingRecord = valid;
    writeU16(&missingRecord, 6, 1);
    CHECK(dp::validateUpstreamResponse(query.data(), query.size(), info,
                                       missingRecord.data(), missingRecord.size(),
                                       upstreamId) ==
          dp::ResponseStatus::MALFORMED_SECTIONS);
  }
  {
    std::vector<uint8_t> trailing = valid;
    trailing.push_back(0xA5);
    CHECK(dp::validateUpstreamResponse(query.data(), query.size(), info,
                                       trailing.data(), trailing.size(),
                                       upstreamId) ==
          dp::ResponseStatus::MALFORMED_SECTIONS);
  }
  {
    std::vector<uint8_t> forwardPointer = valid;
    writeU16(&forwardPointer, 6, 1);
    const size_t ownerOffset = forwardPointer.size();
    const size_t target = ownerOffset + 2;
    forwardPointer.push_back(
        static_cast<uint8_t>(0xC0 | ((target >> 8) & 0x3F)));
    forwardPointer.push_back(static_cast<uint8_t>(target));
    forwardPointer.insert(forwardPointer.end(), 10, 0);
    CHECK(dp::validateUpstreamResponse(
              query.data(), query.size(), info, forwardPointer.data(),
              forwardPointer.size(), upstreamId) ==
          dp::ResponseStatus::MALFORMED_SECTIONS);
  }
  {
    std::vector<uint8_t> pointerLoop = valid;
    writeU16(&pointerLoop, 6, 1);
    const size_t ownerOffset = pointerLoop.size();
    pointerLoop.push_back(1);
    pointerLoop.push_back('a');
    pointerLoop.push_back(
        static_cast<uint8_t>(0xC0 | ((ownerOffset >> 8) & 0x3F)));
    pointerLoop.push_back(static_cast<uint8_t>(ownerOffset));
    pointerLoop.insert(pointerLoop.end(), 10, 0);
    CHECK(dp::validateUpstreamResponse(
              query.data(), query.size(), info, pointerLoop.data(),
              pointerLoop.size(), upstreamId) ==
          dp::ResponseStatus::MALFORMED_SECTIONS);
  }

  std::vector<uint8_t> restored = valid;
  CHECK(dp::setTransactionId(restored.data(), restored.size(), info.clientId));
  CHECK(readU16(restored, 0) == info.clientId);
  CHECK(!dp::setTransactionId(nullptr, 0, info.clientId));
}

void testResponseBuilders() {
  const std::vector<uint8_t> options = {1, 2, 3, 4};
  const std::vector<uint8_t> query =
      makeQuery("example.com", dp::DNS_TYPE_A, dp::DNS_CLASS_IN, 0x0130,
                &options);
  const dp::QueryInfo info = parseValid(query);
  std::vector<uint8_t> output(dp::DNS_PACKET_MAX_BYTES, 0);

  const size_t blockedLength = dp::buildBlockedResponse(
      query.data(), query.size(), info, output.data(), output.size());
  CHECK(blockedLength == info.questionEnd + 16);
  CHECK(readU16(output, 0) == info.clientId);
  CHECK(readU16(output, 4) == 1);
  CHECK(readU16(output, 6) == 1);
  CHECK(readU16(output, 10) == 0);  // OPT removed from local response
  CHECK((readU16(output, 2) & 0x0130) == 0x0130);  // RD/AD/CD preserved
  CHECK(output[blockedLength - 4] == 0 && output[blockedLength - 1] == 0);

  const std::vector<uint8_t> aaaaQuery =
      makeQuery("example.com", dp::DNS_TYPE_AAAA);
  const dp::QueryInfo aaaaInfo = parseValid(aaaaQuery);
  const size_t aaaaLength = dp::buildBlockedResponse(
      aaaaQuery.data(), aaaaQuery.size(), aaaaInfo, output.data(), output.size());
  CHECK(aaaaLength == aaaaInfo.questionEnd);
  CHECK(readU16(output, 6) == 0);

  const size_t failureLength = dp::buildErrorResponse(
      query.data(), query.size(), &info, dp::ResponseCode::SERVER_FAILURE,
      output.data(), output.size());
  CHECK(failureLength == info.questionEnd);
  CHECK((readU16(output, 2) & 0x000F) == 2);
  CHECK(readU16(output, 4) == 1);
  CHECK(readU16(output, 10) == 0);

  const dp::ResponseCode errorCodes[] = {
      dp::ResponseCode::FORMAT_ERROR,
      dp::ResponseCode::NOT_IMPLEMENTED,
      dp::ResponseCode::REFUSED,
      dp::ResponseCode::SERVER_FAILURE,
  };
  for (const dp::ResponseCode code : errorCodes) {
    const size_t length = dp::buildErrorResponse(
        query.data(), query.size(), &info, code, output.data(), output.size());
    CHECK(length == info.questionEnd);
    CHECK((readU16(output, 2) & 0x000F) == static_cast<uint8_t>(code));
    CHECK(readU16(output, 4) == 1);
    CHECK(readU16(output, 6) == 0);
    CHECK(readU16(output, 8) == 0);
    CHECK(readU16(output, 10) == 0);
  }

  CHECK(dp::responseCodeFor(dp::QueryStatus::FORMERR) ==
        dp::ResponseCode::FORMAT_ERROR);
  CHECK(dp::responseCodeFor(dp::QueryStatus::NOTIMP) ==
        dp::ResponseCode::NOT_IMPLEMENTED);
  CHECK(dp::responseCodeFor(dp::QueryStatus::REFUSED) ==
        dp::ResponseCode::REFUSED);
}

struct Candidate {
  dp::Ipv4Endpoint endpoint;
  std::vector<uint8_t> packet;
  uint32_t arrivalMs;
};

int selectCandidate(const std::vector<Candidate>& candidates,
                    const dp::Ipv4Endpoint& expectedEndpoint,
                    const std::vector<uint8_t>& query,
                    const dp::QueryInfo& info, uint16_t upstreamId,
                    uint8_t* examined) {
  *examined = 0;
  for (size_t i = 0; i < candidates.size(); ++i) {
    if (candidates[i].arrivalMs >= dp::DNS_UPSTREAM_TIMEOUT_MS ||
        *examined >= dp::DNS_RESPONSE_CANDIDATE_MAX) {
      break;
    }
    ++(*examined);
    if (!dp::endpointMatches(candidates[i].endpoint, expectedEndpoint)) continue;
    if (dp::validateUpstreamResponse(
            query.data(), query.size(), info, candidates[i].packet.data(),
            candidates[i].packet.size(), upstreamId) ==
        dp::ResponseStatus::VALID) {
      return static_cast<int>(i);
    }
  }
  return -1;
}

void testCandidateSequences() {
  const dp::Ipv4Endpoint upstream{{9, 9, 9, 9}, 53};
  const dp::Ipv4Endpoint forgedEndpoint{{192, 0, 2, 50}, 5300};
  const uint16_t upstreamId = 0xBEEF;
  const std::vector<uint8_t> query = makeQuery("current.example");
  const dp::QueryInfo info = parseValid(query);
  const std::vector<uint8_t> valid = makeResponse(query, info, upstreamId);

  std::vector<uint8_t> wrongId = valid;
  writeU16(&wrongId, 0, 0x1111);
  const std::vector<uint8_t> oldQuery = makeQuery("previous.example");
  const dp::QueryInfo oldInfo = parseValid(oldQuery);
  const std::vector<uint8_t> stale =
      makeResponse(oldQuery, oldInfo, upstreamId);
  std::vector<uint8_t> oversized(dp::DNS_PACKET_MAX_BYTES + 1, 0);

  uint8_t examined = 0;
  {
    const std::vector<Candidate> candidates = {
        {upstream, stale, 1},
        {forgedEndpoint, valid, 2},
        {upstream, wrongId, 3},
        {upstream, valid, 4},
    };
    CHECK(selectCandidate(candidates, upstream, query, info, upstreamId,
                          &examined) == 3);
    CHECK(examined == 4);
  }
  {
    std::vector<Candidate> candidates;
    for (uint8_t i = 0; i < dp::DNS_RESPONSE_CANDIDATE_MAX; ++i) {
      candidates.push_back({upstream, wrongId, i});
    }
    candidates.push_back({upstream, valid, 9});
    CHECK(selectCandidate(candidates, upstream, query, info, upstreamId,
                          &examined) == -1);
    CHECK(examined == dp::DNS_RESPONSE_CANDIDATE_MAX);
  }
  {
    const std::vector<Candidate> candidates = {
        {upstream, oversized, 1}, {upstream, valid, 2}};
    CHECK(selectCandidate(candidates, upstream, query, info, upstreamId,
                          &examined) == 1);
    CHECK(examined == 2);
  }
  {
    const std::vector<Candidate> candidates = {{upstream, valid, 1000}};
    CHECK(selectCandidate(candidates, upstream, query, info, upstreamId,
                          &examined) == -1);
    CHECK(examined == 0);
  }
}

uint32_t nextRandom(uint32_t* state) {
  uint32_t value = *state;
  value ^= value << 13;
  value ^= value >> 17;
  value ^= value << 5;
  *state = value;
  return value;
}

uint64_t runMutations(uint64_t iterations, uint32_t seed) {
  const std::vector<uint8_t> query = makeQuery("www.example.com");
  const dp::QueryInfo info = parseValid(query);
  const std::vector<uint8_t> response = makeResponse(query, info, 0xBEEF);
  uint8_t input[700];
  uint8_t before[700];
  uint64_t checksum = 0;
  uint32_t state = seed == 0 ? 0x4E534D : seed;

  for (uint64_t iteration = 0; iteration < iterations; ++iteration) {
    memset(input, 0xA5, sizeof(input));
    const bool responseBase = (nextRandom(&state) & 1U) != 0;
    const std::vector<uint8_t>& base = responseBase ? response : query;
    size_t length = base.size();
    memcpy(input, base.data(), length);

    switch (nextRandom(&state) % 7U) {
      case 0: {
        length = nextRandom(&state) % 701U;
        for (size_t i = base.size(); i < length; ++i) {
          input[i] = static_cast<uint8_t>(nextRandom(&state));
        }
        break;
      }
      case 1:
        if (length != 0) {
          const size_t at = nextRandom(&state) % length;
          input[at] ^= static_cast<uint8_t>(1U << (nextRandom(&state) & 7U));
        }
        break;
      case 2:
        if (length >= dp::DNS_HEADER_BYTES) {
          const size_t countOffset = 4 + 2 * (nextRandom(&state) % 4U);
          input[countOffset] = static_cast<uint8_t>(nextRandom(&state));
          input[countOffset + 1] = static_cast<uint8_t>(nextRandom(&state));
        }
        break;
      case 3:
        if (length > dp::DNS_HEADER_BYTES) {
          const uint8_t lengths[] = {0, 1, 63, 64, 0x80, 0xC0, 0xFF};
          input[dp::DNS_HEADER_BYTES] =
              lengths[nextRandom(&state) % (sizeof(lengths) / sizeof(lengths[0]))];
        }
        break;
      case 4:
        if (length > dp::DNS_HEADER_BYTES + 1) {
          input[dp::DNS_HEADER_BYTES] = 0xC0;
          input[dp::DNS_HEADER_BYTES + 1] =
              static_cast<uint8_t>(nextRandom(&state));
        }
        break;
      case 5:
        if (length >= 4) {
          input[2] = static_cast<uint8_t>(nextRandom(&state));
          input[3] = static_cast<uint8_t>(nextRandom(&state));
        }
        break;
      case 6:
        length = nextRandom(&state) % (length + 1);
        break;
    }

    memcpy(before, input, sizeof(input));
    dp::QueryInfo mutationInfo{};
    const dp::QueryStatus queryStatus =
        dp::parseClientQuery(input, length, &mutationInfo);
    checksum += static_cast<uint8_t>(queryStatus);
    CHECK(memcmp(input, before, sizeof(input)) == 0);

    const dp::ResponseStatus responseStatus = dp::validateUpstreamResponse(
        query.data(), query.size(), info, input, length, 0xBEEF);
    checksum += static_cast<uint8_t>(responseStatus);
    CHECK(memcmp(input, before, sizeof(input)) == 0);
  }
  return checksum;
}

bool parseUnsigned(const char* text, uint64_t* value) {
  if (text == nullptr || *text == '\0') return false;
  char* end = nullptr;
  const unsigned long long parsed = strtoull(text, &end, 0);
  if (end == text || *end != '\0') return false;
  *value = static_cast<uint64_t>(parsed);
  return true;
}

}  // namespace

int main(int argc, char** argv) {
  uint64_t iterations = 100000;
  uint32_t seed = 0x4E534D;
  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--iterations") == 0 && i + 1 < argc) {
      if (!parseUnsigned(argv[++i], &iterations)) {
        std::cerr << "invalid --iterations\n";
        return 2;
      }
    } else if (strcmp(argv[i], "--seed") == 0 && i + 1 < argc) {
      uint64_t parsedSeed = 0;
      if (!parseUnsigned(argv[++i], &parsedSeed) || parsedSeed > UINT32_MAX) {
        std::cerr << "invalid --seed\n";
        return 2;
      }
      seed = static_cast<uint32_t>(parsedSeed);
    } else {
      std::cerr << "usage: " << argv[0]
                << " [--iterations N] [--seed 0xHEX]\n";
      return 2;
    }
  }

  testConstantsAndEndpoints();
  testParserBoundaries();
  testParserHeaderAndEdnsPolicy();
  testResponseCorrelation();
  testResponseBuilders();
  testCandidateSequences();
  const uint64_t mutationChecksum = runMutations(iterations, seed);

  if (failures != 0) {
    std::cerr << "dns_protocol_tests: FAIL failures=" << failures
              << " checks=" << checks << '\n';
    return 1;
  }
  std::cout << "dns_protocol_tests: PASS checks=" << checks
            << " mutations=" << iterations << " seed=0x" << std::hex
            << std::uppercase << seed << " checksum=0x" << mutationChecksum
            << std::dec << '\n';
  return 0;
}
