package com.heimdallauth.threatintelligencebackend.controller;

import com.heimdallauth.threatintelligencebackend.constants.PhishingDetectionResult;
import com.heimdallauth.threatintelligencebackend.models.DomainCheckRequest;
import com.heimdallauth.threatintelligencebackend.services.PhishDetectionEngine;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.UUID;

@RestController
@RequestMapping("/api/v1/threat-intelligence")
public class ThreatIntelligenceController {
    private final PhishDetectionEngine phishDetectionEngine;

    public ThreatIntelligenceController(PhishDetectionEngine phishDetectionEngine) {
        this.phishDetectionEngine = phishDetectionEngine;
    }

    @PostMapping("/phish-detection")
    public Mono<PhishingDetectionResult> phishDetection(@RequestBody DomainCheckRequest domainCheckRequest) {
        return phishDetectionEngine.calculateEditDistance(domainCheckRequest);
    }
    @GetMapping("/phish-detection")
    public Mono<PhishingDetectionResult> getPhishDetection(@RequestParam("state") UUID state, @RequestParam("domain") String domain) {
        return phishDetectionEngine.calculateEditDistance(new DomainCheckRequest(domain, state));
    }
}
