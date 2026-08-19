#include <cstdint>
#include <cstdio>
#include <cstring>

#include "admin_http_policy.h"
#include "admin_state.h"

static int failures = 0;
#define CHECK(x) do { if (!(x)) { std::printf("failed: %s\n", #x); ++failures; } } while (0)

static bool parse(const char* value, size_t maximum, size_t expected) {
  size_t parsed = 0;
  return admin_http_policy::parseStrictDecimal(value, std::strlen(value), maximum, &parsed) &&
         parsed == expected;
}

int main() {
  using admin_http_policy::FormReadOutcome;
  using admin_http_policy::FormReadStatus;
  using admin_http_policy::PromotionDeadlineAction;
  using admin_http_policy::PromotionPhase;

  CHECK(parse("0", 2048, 0));
  CHECK(parse("123", 2048, 123));
  CHECK(parse("2048", 2048, 2048));
  CHECK(!parse("2049", 2048, 2049));
  CHECK(!parse("", 2048, 0));
  CHECK(!parse(" 1", 2048, 1));
  CHECK(!parse("1 ", 2048, 1));
  CHECK(!parse("+1", 2048, 1));
  CHECK(!parse("-1", 2048, 1));
  CHECK(!parse("1x", 2048, 1));
  CHECK(!parse("999999999999999999999999999999999999999999999999", static_cast<size_t>(-1), 0));
  CHECK(!parse("1", 0, 1));

  CHECK(!admin_http_policy::mustCloseConnection({FormReadStatus::OK, true}));
  CHECK(!admin_http_policy::mustCloseConnection({FormReadStatus::BAD_REQUEST, true}));
  CHECK(admin_http_policy::mustCloseConnection({FormReadStatus::BAD_REQUEST, false}));
  CHECK(admin_http_policy::mustCloseConnection({FormReadStatus::TIMEOUT, true}));
  CHECK(admin_http_policy::mustCloseConnection({FormReadStatus::END_OF_BODY, false}));
  CHECK(admin_http_policy::mustCloseConnection({FormReadStatus::RECEIVE_ERROR, false}));
  CHECK(admin_http_policy::formFramingOutcome(true, 0).status == FormReadStatus::BAD_REQUEST);
  CHECK(!admin_http_policy::formFramingOutcome(true, 0).bodyConsumed);
  CHECK(admin_http_policy::mustCloseConnection(
      admin_http_policy::formFramingOutcome(true, 0)));
  CHECK(admin_http_policy::formFramingOutcome(false, 0).bodyConsumed);
  CHECK(!admin_http_policy::mustCloseConnection(
      admin_http_policy::formFramingOutcome(false, 0)));
  CHECK(admin_http_policy::formReceiveStatus(7, false) == FormReadStatus::OK);
  CHECK(admin_http_policy::formReceiveStatus(-2, true) == FormReadStatus::TIMEOUT);
  CHECK(admin_http_policy::formReceiveStatus(0, false) == FormReadStatus::END_OF_BODY);
  CHECK(admin_http_policy::formReceiveStatus(-1, false) == FormReadStatus::RECEIVE_ERROR);
  CHECK(admin_http_policy::mustCloseConnection({
      admin_http_policy::formReceiveStatus(-2, true), false}));
  CHECK(admin_http_policy::mustCloseConnection({
      admin_http_policy::formReceiveStatus(0, false), false}));
  CHECK(admin_http_policy::mustCloseConnection({
      admin_http_policy::formReceiveStatus(-1, false), false}));
  CHECK(!admin_http_policy::mustClosePendingBody(0));
  CHECK(admin_http_policy::mustClosePendingBody(1));
  CHECK(admin_http_policy::mustCloseRequestBody({false, 0}));
  CHECK(admin_http_policy::mustCloseRequestBody({false, 16}));
  CHECK(admin_http_policy::mustCloseRequestBody({true, 16}));
  CHECK(!admin_http_policy::mustCloseRequestBody({true, 0}));

  CHECK(!admin_state::uploadDeadlineReached(29999, 0, 0));
  CHECK(admin_state::uploadDeadlineReached(30000, 0, 0));
  CHECK(admin_state::uploadDeadlineReached(30001, 0, 0));
  CHECK(admin_http_policy::promotionDeadlineAction(
            PromotionPhase::BEFORE_ACTIVE_TO_OLD, false) == PromotionDeadlineAction::CONTINUE);
  CHECK(admin_http_policy::promotionDeadlineAction(
            PromotionPhase::BEFORE_ACTIVE_TO_OLD, true) == PromotionDeadlineAction::ABORT);
  CHECK(admin_http_policy::promotionDeadlineAction(
            PromotionPhase::AFTER_ACTIVE_TO_OLD, true) == PromotionDeadlineAction::RESTORE_OLD);
  CHECK(admin_http_policy::promotionDeadlineAction(
            PromotionPhase::AFTER_NEW_TO_ACTIVE, true) == PromotionDeadlineAction::RESTORE_OLD);
  CHECK(admin_http_policy::promotionDeadlineAction(
            PromotionPhase::AFTER_CLEANUP, true) == PromotionDeadlineAction::FAIL_CLOSED);

  return failures ? 1 : 0;
}
