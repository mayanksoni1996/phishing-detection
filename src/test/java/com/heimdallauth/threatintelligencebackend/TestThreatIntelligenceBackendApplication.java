package com.heimdallauth.threatintelligencebackend;

import org.springframework.boot.SpringApplication;

public class TestThreatIntelligenceBackendApplication {

    public static void main(String[] args) {
        SpringApplication.from(ThreatIntelligenceBackendApplication::main).with(TestcontainersConfiguration.class).run(args);
    }

}
