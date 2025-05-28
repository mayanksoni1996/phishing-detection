package com.heimdallauth.threatintelligencebackend.documents;

import lombok.*;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.time.Instant;
import java.util.List;

@Document
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
public class TrustedDomain {
    @Id
    private String id;
    private Instant createdOn;
    @Indexed
    private String tld;
    private String domain;
}
