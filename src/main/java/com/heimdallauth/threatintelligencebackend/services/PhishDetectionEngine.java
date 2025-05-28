package com.heimdallauth.threatintelligencebackend.services;

import com.heimdallauth.threatintelligencebackend.algo.EditDistance;
import com.heimdallauth.threatintelligencebackend.constants.PhishingDetectionResult;
import com.heimdallauth.threatintelligencebackend.dm.TrustedDomainDataManager;
import com.heimdallauth.threatintelligencebackend.documents.TrustedDomain;
import com.heimdallauth.threatintelligencebackend.models.DomainCheckRequest;
import com.heimdallauth.threatintelligencebackend.utils.DomainUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

@Service
@Slf4j
@RequiredArgsConstructor
public class PhishDetectionEngine {
    //TODO Replace with cache
    private final TrustedDomainDataManager trustedDomainDataManager;

    public Mono<PhishingDetectionResult> calculateEditDistance(DomainCheckRequest domainCheckRequest){
        String domainUnderCheck = domainCheckRequest.domainUnderCheck();
        return trustedDomainDataManager.getTrustedDomainsByTld(DomainUtils.getTldFromDomain(domainUnderCheck))
                .map(dbResult -> EditDistance.calculateEditDistance(domainUnderCheck, dbResult.getDomain()))
                .filter(editDistance -> editDistance == 0 || editDistance <=2)
                .map(calculatedEditDistance -> {
                    if(calculatedEditDistance ==0){
                        return PhishingDetectionResult.NOT_PHISHING;
                    }else{
                        return PhishingDetectionResult.POSSIBLE_PHISHING;
                    }
                }).next().defaultIfEmpty(PhishingDetectionResult.NOT_PHISHING);
    }
}
