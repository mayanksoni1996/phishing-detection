package com.heimdallauth.threatintelligencebackend.dm;

import com.heimdallauth.threatintelligencebackend.documents.TrustedDomain;
import com.heimdallauth.threatintelligencebackend.utils.DomainUtils;
import com.heimdallauth.threatintelligencebackend.utils.FileSystemUtils;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.mongodb.core.ReactiveMongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

@Repository
@RequiredArgsConstructor
@Slf4j
public class TrustedDomainDataManager {
    private final ReactiveMongoTemplate mongoTemplate;

    @PostConstruct
    private void triggerDataLoad(){
        log.info("Starting data load");
        Mono<Long> recordsCount = mongoTemplate.count(new Query(), TrustedDomain.class);
        recordsCount.subscribe(count -> {
            if(count == 0){
                log.info("No records found, loading data from CSV");
                loadDataFromCsv();
            }else{
                log.info("Records already exist, skipping data load");
            }
        });
    }

    private void loadDataFromCsv() {
        List<String[]> csvRecords = FileSystemUtils.readCsvFile(Paths.get(System.getenv("TRANCOFILE_PATH")).toAbsolutePath().normalize());
        log.debug("CSV Records: {}", csvRecords.size());
        saveTrustedDomains(csvRecords.stream().map(row -> row[1]).collect(Collectors.toList()));
        log.info("Finished loading data from CSV");
    }

    private void saveTrustedDomains(List<String> trustedDomains) {
        Instant startDuration = Instant.now();
        int batchSize = 100000;
        List<List<String>> partitions = DomainUtils.partitionList(trustedDomains, batchSize);
        log.info("Starting saving trusted domains");
        Flux.fromIterable(partitions)
            .concatMap(partition -> {
                List<TrustedDomain> trustedDomainList = partition.stream()
                    .map(domain -> TrustedDomain.builder()
                        .id(UUID.randomUUID().toString())
                        .createdOn(Instant.now())
                        .tld(DomainUtils.getTldFromDomain(domain))
                        .domain(domain)
                        .build())
                    .collect(Collectors.toList());

                return mongoTemplate.insertAll(trustedDomainList)
                    .doOnError(error -> log.error("Error inserting trusted domains: {}", error.getMessage()));
            })
            .doOnComplete(() -> log.info("All trusted domains inserted successfully"))
            .doOnError(error -> log.error("Error during batch insert: {}", error.getMessage()))
            .subscribe();
        log.debug("Finished saving trusted domains, Total Run Duration: {}", Duration.between(startDuration, Instant.now()));
    }

    public Flux<TrustedDomain> getTrustedDomainsByTld(String tld) {
        return mongoTemplate.find(Query.query(Criteria.where("tld").is(tld)), TrustedDomain.class)
            .switchIfEmpty(Flux.error(new RuntimeException("No trusted domain found for TLD: " + tld)));
    }
}
