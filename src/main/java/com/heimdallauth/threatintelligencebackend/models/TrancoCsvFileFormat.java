package com.heimdallauth.threatintelligencebackend.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

@Data
public class TrancoCsvFileFormat {
    @JsonProperty("rank")
    private long rank;
    @JsonProperty("domain")
    private String domain;
}
