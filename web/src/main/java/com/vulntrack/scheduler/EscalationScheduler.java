package com.vulntrack.scheduler;

import com.vulntrack.service.VulnTrackService;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

@Component
@ConditionalOnProperty(name = "vulntrack.escalation.enabled", havingValue = "true", matchIfMissing = true)
public class EscalationScheduler {

    private static final Logger log = LoggerFactory.getLogger(EscalationScheduler.class);

    private final VulnTrackService vulnTrackService;

    public EscalationScheduler(VulnTrackService vulnTrackService) {
        this.vulnTrackService = vulnTrackService;
    }

    @Scheduled(cron = "${vulntrack.escalation.cron:0 0 * * * *}")
    public void escalateOverdueFindings() {
        int escalated = vulnTrackService.escalateOverdueFindings();
        if (escalated > 0) {
            log.info("Escalated {} overdue findings.", escalated);
        }
    }
}
