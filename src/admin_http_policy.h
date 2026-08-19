#pragma once

#include <stddef.h>
#include <stdint.h>

// Pure, allocation-free policy used by the esp_http_server adapters.  Keeping
// these decisions independent from Arduino types makes their security
// boundaries native-testable.
namespace admin_http_policy {

enum class FormReadStatus : uint8_t {
  OK,
  BAD_REQUEST,
  TIMEOUT,
  END_OF_BODY,
  RECEIVE_ERROR,
};

struct FormReadOutcome {
  FormReadStatus status;
  bool bodyConsumed;
};

// A visible Transfer-Encoding makes request->content_len untrustworthy on the
// supported server API.  Do not treat such a request as an empty safe body.
inline FormReadOutcome formFramingOutcome(bool hasTransferEncoding,
                                          size_t contentLength) {
  return {FormReadStatus::BAD_REQUEST,
          !hasTransferEncoding && contentLength == 0};
}

inline FormReadStatus formReceiveStatus(int received, bool receiveTimedOut) {
  if (received > 0) return FormReadStatus::OK;
  if (receiveTimedOut) return FormReadStatus::TIMEOUT;
  if (received == 0) return FormReadStatus::END_OF_BODY;
  return FormReadStatus::RECEIVE_ERROR;
}

// Accept ASCII decimal only.  The caller supplies the maximum accepted value,
// so overflow and out-of-policy values fail before a result is published.
inline bool parseStrictDecimal(const char* input, size_t length, size_t maximum,
                               size_t* parsedValue) {
  if (!input || !length || !parsedValue) return false;
  size_t value = 0;
  for (size_t index = 0; index < length; ++index) {
    const char byte = input[index];
    if (byte < '0' || byte > '9') return false;
    const size_t digit = static_cast<size_t>(byte - '0');
    if (value > maximum / 10 ||
        (value == maximum / 10 && digit > maximum % 10)) return false;
    value = value * 10 + digit;
  }
  *parsedValue = value;
  return true;
}

// A handler must not return ESP_OK when the request body is still pending:
// esp_http_server would otherwise drain it outside this bounded request path.
inline bool mustCloseConnection(FormReadOutcome outcome) {
  return !outcome.bodyConsumed || outcome.status == FormReadStatus::TIMEOUT ||
         outcome.status == FormReadStatus::END_OF_BODY ||
         outcome.status == FormReadStatus::RECEIVE_ERROR;
}

inline bool mustClosePendingBody(size_t remainingBytes) {
  return remainingBytes != 0;
}

struct RequestBodyFraming {
  bool trustworthy;
  size_t remainingBytes;
};

// A rejected request is safe to keep alive only when its framing was accepted
// and the application can prove that no body bytes remain.
inline bool mustCloseRequestBody(RequestBodyFraming framing) {
  return !framing.trustworthy || mustClosePendingBody(framing.remainingBytes);
}

enum class PromotionPhase : uint8_t {
  BEFORE_ACTIVE_TO_OLD,
  AFTER_ACTIVE_TO_OLD,
  AFTER_NEW_TO_ACTIVE,
  AFTER_CLEANUP,
};

enum class PromotionDeadlineAction : uint8_t {
  CONTINUE,
  ABORT,
  RESTORE_OLD,
  FAIL_CLOSED,
};

// The transaction has an old active list until cleanup completes.  An expiry
// before then can restore it; expiry after cleanup must fail closed rather than
// reporting an out-of-deadline success.
inline PromotionDeadlineAction promotionDeadlineAction(PromotionPhase phase,
                                                        bool deadlineExpired) {
  if (!deadlineExpired) return PromotionDeadlineAction::CONTINUE;
  if (phase == PromotionPhase::BEFORE_ACTIVE_TO_OLD) {
    return PromotionDeadlineAction::ABORT;
  }
  if (phase == PromotionPhase::AFTER_CLEANUP) {
    return PromotionDeadlineAction::FAIL_CLOSED;
  }
  return PromotionDeadlineAction::RESTORE_OLD;
}

}  // namespace admin_http_policy
