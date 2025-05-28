package com.heimdallauth.threatintelligencebackend.utils;

import reactor.core.publisher.Flux;

import java.util.List;

public class DomainUtils {
    public static String getTldFromDomain(String domain) {
        if (domain == null || !domain.contains(".")) {
            throw new IllegalArgumentException("Invalid domain name");
        }
        String[] parts = domain.split("\\.");
        return parts[parts.length - 1];
    }
    public static <T> List<List<T>> partitionList(List<T> list, int size){
        return Flux.fromIterable(list)
                .buffer(size)
                .collectList()
                .block();
    }
}