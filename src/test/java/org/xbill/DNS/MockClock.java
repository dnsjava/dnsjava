// SPDX-License-Identifier: BSD-3-Clause
package org.xbill.DNS;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class MockClock extends Clock {
  private final Clock baseClock;
  private Duration offset = Duration.ZERO;

  public void advance(Duration offset) {
    this.offset = offset;
  }

  @Override
  public ZoneId getZone() {
    return baseClock.getZone();
  }

  @Override
  public Clock withZone(ZoneId zone) {
    return baseClock.withZone(zone);
  }

  @Override
  public Instant instant() {
    return baseClock.instant().plus(offset);
  }
}
