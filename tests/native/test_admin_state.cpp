#include <cstdint>
#include <cstdio>
#include "admin_state.h"

static int failures = 0;
#define CHECK(x) do { if (!(x)) { std::printf("failed: %s\n", #x); ++failures; } } while (0)

static admin_state::BootGesture press(uint32_t down, uint32_t up) {
  admin_state::BootGestureTracker tracker;
  tracker.update(false, 0); tracker.update(false, 60);
  tracker.update(true, down); tracker.update(false, up); return tracker.update(false, up + 60);
}

int main() {
  using admin_state::BootGesture;
  using admin_state::BootAction;
  using admin_state::DnsStartupAction;
  using admin_state::RuntimeState;
  // Hold duration is measured at release, then action is emitted only after
  // the stable-HIGH debounce interval.
  CHECK(press(100, 2000) == BootGesture::NONE);           // 1.9 s
  CHECK(press(100, 2100) == BootGesture::ADMIN_WINDOW);   // 2.0 s
  CHECK(press(100, 4000) == BootGesture::ADMIN_WINDOW);   // 3.9 s
  CHECK(press(100, 4100) == BootGesture::NONE);           // 4.0 s
  CHECK(press(100, 5000) == BootGesture::NONE);           // 4.9 s
  CHECK(press(100, 5100) == BootGesture::RECOVERY);       // 5.0 s
  CHECK(press(100, 2099) == BootGesture::NONE);
  CHECK(press(100, 2100) == BootGesture::ADMIN_WINDOW);
  CHECK(press(100, 4099) == BootGesture::ADMIN_WINDOW);
  CHECK(press(100, 4100) == BootGesture::NONE);
  CHECK(press(100, 5099) == BootGesture::NONE);
  CHECK(press(100, 5100) == BootGesture::RECOVERY);
  CHECK(press(UINT32_MAX - 100, 1950) == BootGesture::ADMIN_WINDOW);
  admin_state::BootGestureTracker held;
  CHECK(held.update(false, 0) == BootGesture::NONE);
  CHECK(held.update(false, 60) == BootGesture::NONE);
  CHECK(held.update(true, 100) == BootGesture::NONE);
  CHECK(held.update(false, 2100) == BootGesture::NONE);  // release edge, not action yet
  CHECK(held.update(false, 2159) == BootGesture::NONE);
  CHECK(held.update(false, 2160) == BootGesture::ADMIN_WINDOW);
  CHECK(admin_state::bootActionFor(RuntimeState::DNS_ONLY, BootGesture::ADMIN_WINDOW) ==
        BootAction::OPEN_ADMIN);
  CHECK(admin_state::bootActionFor(RuntimeState::DNS_ONLY, BootGesture::RECOVERY) ==
        BootAction::OPEN_PROVISIONING);
  CHECK(admin_state::bootActionFor(RuntimeState::DNS_ONLY, BootGesture::NONE) ==
        BootAction::NONE);
  CHECK(admin_state::bootActionFor(RuntimeState::OFFLINE_RECOVERY_REQUIRED,
                                   BootGesture::RECOVERY) == BootAction::OPEN_PROVISIONING);
  CHECK(admin_state::bootActionFor(RuntimeState::ADMIN_PSK_REQUIRED,
                                   BootGesture::RECOVERY) == BootAction::OPEN_PROVISIONING);
  const RuntimeState restrictedStates[] = {
      RuntimeState::ADMIN_AP_WINDOW, RuntimeState::PROVISIONING_AP};
  for (RuntimeState state : restrictedStates) {
    CHECK(admin_state::bootActionFor(state, BootGesture::NONE) == BootAction::NONE);
    CHECK(admin_state::bootActionFor(state, BootGesture::ADMIN_WINDOW) == BootAction::NONE);
    CHECK(admin_state::bootActionFor(state, BootGesture::RECOVERY) == BootAction::NONE);
  }
  CHECK(admin_state::dnsStartupAction(true, false) == DnsStartupAction::STARTED);
  CHECK(admin_state::dnsStartupAction(true, true) == DnsStartupAction::STARTED);
  CHECK(admin_state::dnsStartupAction(false, false) == DnsStartupAction::RETRY);
  CHECK(admin_state::dnsStartupAction(false, true) == DnsStartupAction::FAIL_CLOSED);
  CHECK(admin_state::deadlineReached(4, UINT32_MAX - 5, 10));
  CHECK(admin_state::acceptsNewAdminWork(299999, 0));
  CHECK(!admin_state::acceptsNewAdminWork(300000, 0));
  CHECK(!admin_state::mustCloseAdminWindow(299999, 0, false));
  CHECK(admin_state::mustCloseAdminWindow(300000, 0, false));
  CHECK(!admin_state::mustCloseAdminWindow(300000, 0, true));
  CHECK(!admin_state::mustCloseAdminWindow(329999, 0, true));
  CHECK(admin_state::mustCloseAdminWindow(330000, 0, true));
  CHECK(!admin_state::deadlineReached(29999, 0, admin_state::kUploadDeadlineMs));
  CHECK(admin_state::deadlineReached(30000, 0, admin_state::kUploadDeadlineMs));
  CHECK(admin_state::uploadDeadlineDuration(0, 299999) == 30000);
  CHECK(admin_state::uploadDeadlineDuration(0, 300000) == 30000);
  CHECK(admin_state::uploadDeadlineDuration(0, 300001) == 29999);
  CHECK(admin_state::uploadDeadlineDuration(0, 329999) == 1);
  CHECK(admin_state::uploadDeadlineDuration(0, 330000) == 0);
  CHECK(!admin_state::uploadDeadlineReached(299999, 0, 299999));
  CHECK(!admin_state::uploadDeadlineReached(329998, 0, 299999));
  CHECK(admin_state::uploadDeadlineReached(329999, 0, 299999));
  CHECK(admin_state::uploadDeadlineReached(330000, 0, 300001));
  CHECK(admin_state::uploadDeadlineReached(330001, 0, 300001));
  admin_state::WindowBudget budget;
  CHECK(!budget.recordPromotion(true));  // No accepted start, no promotion.
  CHECK(budget.recordUploadStart());
  CHECK(budget.recordUploadStart());
  CHECK(budget.recordUploadStart());
  CHECK(!budget.recordUploadStart());
  CHECK(budget.promotions() == 0);  // A failed transaction never records promotion.
  CHECK(!budget.recordPromotion(false)); CHECK(budget.promotions() == 0);
  CHECK(budget.recordPromotion(true)); CHECK(budget.promotions() == 1);
  CHECK(!budget.recordPromotion(true));
  CHECK(!budget.allowUploadStart());
  for (int i = 0; i < 9; ++i) CHECK(!budget.loginFailed());
  CHECK(budget.loginFailed());
  return failures ? 1 : 0;
}
