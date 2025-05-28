package com.heimdallauth.threatintelligencebackend.models;

import java.util.UUID;

public record DomainCheckRequest(
        String domainUnderCheck,
        UUID state
) {
}
