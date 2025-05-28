package com.heimdallauth.threatintelligencebackend.utils;

import com.opencsv.CSVReader;
import com.opencsv.exceptions.CsvValidationException;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;

import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class FileSystemUtils {
    public static List<String[]> readCsvFile(Path absolutePath) {
        Resource csvResource = new FileSystemResource(absolutePath.toFile());
        List<String[]> csvRecords = new ArrayList<>();
        try (CSVReader reader = new CSVReader(new FileReader(csvResource.getFile()))) {
            reader.readNext(); // Skip header line
            String[] line;
            while ((line = reader.readNext()) != null) {
                csvRecords.add(line);
            }
            return csvRecords;
        } catch (IOException | CsvValidationException e) {
            throw new RuntimeException(e);
        }
    }
}
