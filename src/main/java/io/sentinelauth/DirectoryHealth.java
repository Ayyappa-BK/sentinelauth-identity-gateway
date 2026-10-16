package io.sentinelauth;

import io.micrometer.core.instrument.MeterRegistry;
import java.util.concurrent.atomic.AtomicInteger;
import org.springframework.boot.actuate.health.*;
import org.springframework.stereotype.Component;

@Component("directory")
public class DirectoryHealth implements HealthIndicator {
  private final LdapDirectory directory;
  private final AtomicInteger available = new AtomicInteger(0);

  public DirectoryHealth(LdapDirectory directory, MeterRegistry registry) {
    this.directory = directory;
    registry.gauge("sentinel.directory.available", available);
  }

  public Health health() {
    try {
      directory.checkAvailability();
      available.set(1);
      return Health.up().build();
    } catch (Exception ex) {
      available.set(0);
      return Health.down().build();
    }
  }
}
