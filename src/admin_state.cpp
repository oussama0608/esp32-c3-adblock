#include "admin_state.h"

namespace admin_state {

bool deadlineReached(uint32_t now, uint32_t started, uint32_t duration) {
  return static_cast<uint32_t>(now - started) >= duration;
}

BootAction bootActionFor(RuntimeState state, BootGesture gesture) {
  if (state == RuntimeState::DNS_ONLY) {
    if (gesture == BootGesture::ADMIN_WINDOW) return BootAction::OPEN_ADMIN;
    if (gesture == BootGesture::RECOVERY) return BootAction::OPEN_PROVISIONING;
  }
  if ((state == RuntimeState::OFFLINE_RECOVERY_REQUIRED ||
       state == RuntimeState::ADMIN_PSK_REQUIRED) &&
      gesture == BootGesture::RECOVERY) {
    return BootAction::OPEN_PROVISIONING;
  }
  return BootAction::NONE;
}

DnsStartupAction dnsStartupAction(bool bound, bool retryUsed) {
  if (bound) return DnsStartupAction::STARTED;
  return retryUsed ? DnsStartupAction::FAIL_CLOSED : DnsStartupAction::RETRY;
}

bool acceptsNewAdminWork(uint32_t now, uint32_t started) {
  return !deadlineReached(now, started, kAdminWindowMs);
}

bool mustCloseAdminWindow(uint32_t now, uint32_t started, bool uploadInFlight) {
  return deadlineReached(now, started, kAdminHardCeilingMs) ||
         (!uploadInFlight && !acceptsNewAdminWork(now, started));
}

bool uploadDeadlineReached(uint32_t now, uint32_t adminWindowStarted,
                           uint32_t uploadStarted) {
  return deadlineReached(now, uploadStarted, kUploadDeadlineMs) ||
         deadlineReached(now, adminWindowStarted, kAdminHardCeilingMs);
}

uint32_t uploadDeadlineDuration(uint32_t adminWindowStarted,
                                uint32_t uploadStarted) {
  const uint32_t elapsed = uploadStarted - adminWindowStarted;
  if (elapsed >= kAdminHardCeilingMs) return 0;
  const uint32_t remainingHardWindow = kAdminHardCeilingMs - elapsed;
  return remainingHardWindow < kUploadDeadlineMs ? remainingHardWindow : kUploadDeadlineMs;
}

bool WindowBudget::recordUploadStart() {
  if (!allowUploadStart()) return false;
  ++uploadStarts_;
  return true;
}

bool WindowBudget::recordPromotion(bool promotionSucceeded) {
  if (!promotionSucceeded || promotions_ || !uploadStarts_) return false;
  ++promotions_;
  return true;
}

void BootGestureTracker::reset() {
  initialReleaseSeen_ = false;
  pressed_ = false;
  releaseTracking_ = false;
  pressedSince_ = 0;
  releasedSince_ = 0;
}

BootGesture BootGestureTracker::update(bool pressed, uint32_t now) {
  if (!initialReleaseSeen_) {
    if (!pressed) {
      if (!releaseTracking_) {
        releaseTracking_ = true;
        releasedSince_ = now;
      }
      if (deadlineReached(now, releasedSince_, kReleaseStableMs)) {
        initialReleaseSeen_ = true;
        releaseTracking_ = false;
      }
    } else {
      releaseTracking_ = false;
    }
    return BootGesture::NONE;
  }

  if (pressed) {
    releaseTracking_ = false;
    if (!pressed_) {
      pressed_ = true;
      pressedSince_ = now;
    }
    return BootGesture::NONE;
  }

  if (!pressed_) return BootGesture::NONE;
  if (!releaseTracking_) {
    releaseTracking_ = true;
    releasedSince_ = now;
    return BootGesture::NONE;
  }
  if (!deadlineReached(now, releasedSince_, kReleaseStableMs)) return BootGesture::NONE;

  // Classify the LOW duration at the release edge, not after the debounce
  // period; otherwise each threshold would be shifted by kReleaseStableMs.
  const uint32_t held = releasedSince_ - pressedSince_;
  pressed_ = false;
  releaseTracking_ = false;
  if (held >= kRecoveryHoldMinMs) return BootGesture::RECOVERY;
  if (held >= kAdminHoldMinMs && held < kAdminHoldMaxExclusiveMs) {
    return BootGesture::ADMIN_WINDOW;
  }
  return BootGesture::NONE;
}

}  // namespace admin_state
