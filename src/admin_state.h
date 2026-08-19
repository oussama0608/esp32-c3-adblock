#pragma once

#include <stdint.h>

namespace admin_state {

enum class BootGesture : uint8_t { NONE, ADMIN_WINDOW, RECOVERY };
enum class RuntimeState : uint8_t {
  DNS_ONLY,
  ADMIN_AP_WINDOW,
  PROVISIONING_AP,
  OFFLINE_RECOVERY_REQUIRED,
  ADMIN_PSK_REQUIRED,
};
enum class BootAction : uint8_t { NONE, OPEN_ADMIN, OPEN_PROVISIONING };
enum class DnsStartupAction : uint8_t { STARTED, RETRY, FAIL_CLOSED };

static constexpr uint32_t kAdminHoldMinMs = 2000;
static constexpr uint32_t kAdminHoldMaxExclusiveMs = 4000;
static constexpr uint32_t kRecoveryHoldMinMs = 5000;
static constexpr uint32_t kReleaseStableMs = 60;
static constexpr uint32_t kAdminWindowMs = 5UL * 60UL * 1000UL;
static constexpr uint32_t kAdminHardCeilingMs = 330UL * 1000UL;
static constexpr uint32_t kProvisioningWindowMs = 10UL * 60UL * 1000UL;
static constexpr uint32_t kUploadDeadlineMs = 30UL * 1000UL;

// The button is classified only after a stable release.  This avoids treating
// GPIO9's boot-time strapping level as an application authorization gesture.
class BootGestureTracker {
 public:
  BootGesture update(bool pressed, uint32_t now);
  void reset();

 private:
  bool initialReleaseSeen_ = false;
  bool pressed_ = false;
  bool releaseTracking_ = false;
  uint32_t pressedSince_ = 0;
  uint32_t releasedSince_ = 0;
};

bool deadlineReached(uint32_t now, uint32_t started, uint32_t duration);
BootAction bootActionFor(RuntimeState state, BootGesture gesture);
DnsStartupAction dnsStartupAction(bool bound, bool retryUsed);
bool acceptsNewAdminWork(uint32_t now, uint32_t started);
bool mustCloseAdminWindow(uint32_t now, uint32_t started, bool uploadInFlight);
bool uploadDeadlineReached(uint32_t now, uint32_t adminWindowStarted,
                           uint32_t uploadStarted);
uint32_t uploadDeadlineDuration(uint32_t adminWindowStarted,
                                uint32_t uploadStarted);

class WindowBudget {
 public:
  bool allowUploadStart() const { return uploadStarts_ < 3 && promotions_ < 1; }
  bool recordUploadStart();
  bool recordPromotion(bool promotionSucceeded);
  bool loginFailed() { return ++failedLogins_ >= 10; }
  uint8_t uploadStarts() const { return uploadStarts_; }
  uint8_t promotions() const { return promotions_; }
  uint8_t failedLogins() const { return failedLogins_; }

 private:
  uint8_t uploadStarts_ = 0;
  uint8_t promotions_ = 0;
  uint8_t failedLogins_ = 0;
};

}  // namespace admin_state
