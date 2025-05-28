package com.heimdallauth.threatintelligencebackend.config;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "threat.intel.properties")
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class ThreatIntelConfig {
    private String trancoListPath;
}
