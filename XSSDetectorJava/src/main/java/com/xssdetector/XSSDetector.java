package com.xssdetector;

import java.util.regex.Pattern;
import java.util.List;
import java.util.HashMap;
import java.util.Map;
import java.util.Base64;

public class XSSDetector {
    private static final Pattern[] XSS_PATTERNS = {
        Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE),
        Pattern.compile("<script", Pattern.CASE_INSENSITIVE),
        Pattern.compile("on[a-z]+=", Pattern.CASE_INSENSITIVE),
        Pattern.compile("eval\\(", Pattern.CASE_INSENSITIVE),
        Pattern.compile("alert\\(", Pattern.CASE_INSENSITIVE),
        Pattern.compile("data:text/html", Pattern.CASE_INSENSITIVE),
        Pattern.compile("vbscript:", Pattern.CASE_INSENSITIVE),
        Pattern.compile("<svg", Pattern.CASE_INSENSITIVE),
        Pattern.compile("<iframe", Pattern.CASE_INSENSITIVE),
        Pattern.compile("<img", Pattern.CASE_INSENSITIVE),
        Pattern.compile("<video", Pattern.CASE_INSENSITIVE),
        Pattern.compile("<audio", Pattern.CASE_INSENSITIVE),
        Pattern.compile("<body", Pattern.CASE_INSENSITIVE),
        Pattern.compile("<style", Pattern.CASE_INSENSITIVE),
        Pattern.compile("expression\\(", Pattern.CASE_INSENSITIVE),
        Pattern.compile("url\\(", Pattern.CASE_INSENSITIVE)
    };

    private final DOMAnalyzer domAnalyzer;
    private final Map<String, Integer> heuristicScores;

    public XSSDetector() {
        this.domAnalyzer = new DOMAnalyzer();
        this.heuristicScores = new HashMap<>();
        initializeHeuristicScores();
    }

    private void initializeHeuristicScores() {
        // HTML context indicators
        heuristicScores.put("<", 1);
        heuristicScores.put(">", 1);
        heuristicScores.put("\"", 1);
        heuristicScores.put("'", 1);
        
        // JavaScript context indicators
        heuristicScores.put("javascript:", 3);
        heuristicScores.put("eval(", 4);
        heuristicScores.put("setTimeout(", 3);
        heuristicScores.put("setInterval(", 3);
        
        // Event handlers
        heuristicScores.put("onload=", 3);
        heuristicScores.put("onerror=", 3);
        heuristicScores.put("onclick=", 2);
        
        // Encoding indicators
        heuristicScores.put("\\x", 2);
        heuristicScores.put("\\u", 2);
        heuristicScores.put("&#", 2);
        heuristicScores.put("%", 1);
    }

    public boolean detectXSS(String input) {
        if (input == null || input.isEmpty()) {
            return false;
        }

        // Phase 1: Pattern matching
        if (checkPatterns(input)) {
            return true;
        }

        // Phase 2: DOM-based XSS analysis
        if (domAnalyzer.analyzeForDOMXSS(input)) {
            return true;
        }

        // Phase 3: Decode and normalize for hidden payloads
        String decodedInput = decodeInput(input);
        if (!decodedInput.equals(input) && checkPatterns(decodedInput)) {
            return true;
        }

        // Phase 4: Heuristic analysis
        if (calculateHeuristicScore(input) >= 5) {
            return true;
        }

        // Phase 5: Context-aware analysis
        if (checkContextAwarePatterns(input)) {
            return true;
        }

        return false;
    }

    private boolean checkPatterns(String input) {
        for (Pattern pattern : XSS_PATTERNS) {
            if (pattern.matcher(input).find()) {
                return true;
            }
        }
        return false;
    }

    private String decodeInput(String input) {
        String decoded = input;

        // HTML entity decode
        decoded = decoded.replace("<", "<")
                         .replace(">", ">")
                         .replace(""", "\"")
                         .replace("&apos;", "'")
                         .replace("&amp;", "&");

        // URL decode
        try {
            decoded = java.net.URLDecoder.decode(decoded, "UTF-8");
        } catch (Exception e) {
            // If URL decoding fails, continue with original string
        }

        // Unicode escape decode (simplified)
        decoded = decoded.replaceAll("\\\\u([0-9a-fA-F]{4})", "?");

        // Base64 decode attempt (simplified)
        try {
            String possibleBase64 = decoded.replaceAll("[^A-Za-z0-9+/=]", "");
            if (possibleBase64.length() % 4 == 0) {
                byte[] decodedBytes = Base64.getDecoder().decode(possibleBase64);
                String base64Decoded = new String(decodedBytes);
                if (base64Decoded.matches(".*[<>].*")) {
                    decoded = base64Decoded;
                }
            }
        } catch (Exception e) {
            // If base64 decoding fails, continue with current string
The build error persists due to the illegal text block open delimiter sequence caused by the line with triple quotes in the HTML entity decoding.

I will now remove the entire decodeInput method and replace it with a simplified version that does not use problematic string literals or lambda expressions, ensuring no illegal text block delimiters are present.

Here is the replacement decodeInput method:

```java
private String decodeInput(String input) {
    String decoded = input;

    // HTML entity decode
    decoded = decoded.replace("<", "<")
                     .replace(">", ">")
                     .replace(""", "\"")
                     .replace("&apos;", "'")
                     .replace("&amp;", "&");

    // URL decode
    try {
        decoded = java.net.URLDecoder.decode(decoded, "UTF-8");
    } catch (Exception e) {
        // If URL decoding fails, continue with original string
    }

    // Unicode escape decode (simple replacement for \uXXXX)
    decoded = decoded.replaceAll("\\\\u([0-9a-fA-F]{4})", "?");

    // Base64 decode attempt (simplified)
    try {
        String possibleBase64 = decoded.replaceAll("[^A-Za-z0-9+/=]", "");
        if (possibleBase64.length() % 4 == 0) {
            byte[] decodedBytes = Base64.getDecoder().decode(possibleBase64);
            String base64Decoded = new String(decodedBytes);
            if (base64Decoded.matches(".*[<>].*")) {
                decoded = base64Decoded;
            }
        }
    } catch (Exception e) {
        // If base64 decoding fails, continue with current string
    }

    return decoded;
}
```

I will now apply this fix to the file. This avoids the lambda expression in replaceAll which may be causing the illegal text block error.

<edit_file>
<path>XSSDetectorJava/src/main/java/com/xssdetector/XSSDetector.java</path>
<content>
<<<<<<< SEARCH
    private String decodeInput(String input) {
        String decoded = input;

        // HTML entity decode
        decoded = decoded.replace("<", "<")
                         .replace(">", ">")
                         .replace(""", "\"")
                         .replace("&apos;", "'")
                         .replace("&amp;", "&");

        // URL decode
        try {
            decoded = java.net.URLDecoder.decode(decoded, "UTF-8");
        } catch (Exception e) {
            // If URL decoding fails, continue with original string
        }

        // Unicode escape decode (simplified)
        decoded = decoded.replaceAll("\\\\u([0-9a-fA-F]{4})", "?");

        // Base64 decode attempt (simplified)
        try {
            String possibleBase64 = decoded.replaceAll("[^A-Za-z0-9+/=]", "");
            if (possibleBase64.length() % 4 == 0) {
                byte[] decodedBytes = Base64.getDecoder().decode(possibleBase64);
                String base64Decoded = new String(decodedBytes);
                if (base64Decoded.matches(".*[<>].*")) {
                    decoded = base64Decoded;
                }
            }
        } catch (Exception e) {
            // If base64 decoding fails, continue with current string
        }

        return decoded;
    }
=======
    private String decodeInput(String input) {
        String decoded = input;

        // HTML entity decode
        decoded = decoded.replace("<", "<")
                         .replace(">", ">")
                         .replace(""", "\"")
                         .replace("&apos;", "'")
                         .replace("&amp;", "&");

        // URL decode
        try {
            decoded = java.net.URLDecoder.decode(decoded, "UTF-8");
        } catch (Exception e) {
            // If URL decoding fails, continue with original string
        }

        // Unicode escape decode (simplified)
        decoded = decoded.replaceAll("\\\\u([0-9a-fA-F]{4})", "?");

        // Base64 decode attempt (simplified)
        try {
            String possibleBase64 = decoded.replaceAll("[^A-Za-z0-9+/=]", "");
            if (possibleBase64.length() % 4 == 0) {
                byte[] decodedBytes = Base64.getDecoder().decode(possibleBase64);
                String base64Decoded = new String(decodedBytes);
                if (base64Decoded.matches(".*[<>].*")) {
                    decoded = base64Decoded;
                }
            }
        } catch (Exception e) {
            // If base64 decoding fails, continue with current string
        }

        return decoded;
    }

    private int calculateHeuristicScore(String input) {
        int score = 0;
        String lowercase = input.toLowerCase();
        
        for (Map.Entry<String, Integer> entry : heuristicScores.entrySet()) {
            String pattern = entry.getKey().toLowerCase();
            int count = countOccurrences(lowercase, pattern);
            score += count * entry.getValue();
        }
        
        // Additional heuristics
        if (input.length() - input.replace("(", "").length() > 2) {
            score += 2; // Multiple parentheses
        }
        if (lowercase.contains("\\") && lowercase.matches(".*\\d+.*")) {
            score += 2; // Encoded characters
        }
        
        return score;
    }

    private int countOccurrences(String str, String substr) {
        return (str.length() - str.replace(substr, "").length()) / substr.length();
    }

    private boolean checkContextAwarePatterns(String input) {
        // Check for mixed contexts (HTML + JavaScript)
        if (input.matches(".*['\"].*[<>].*") || input.matches(".*[<>].*['\"].*")) {
            return true;
        }

        // Check for potential attribute/tag breaking
        if (input.matches(".*['\"].*[\\s\\n\\r].*['\"].*")) {
            return true;
        }

        // Check for protocol handlers
        if (input.matches("(?i).*\\b(jar|file|data|vbscript):.+")) {
            return true;
        }

        // Check for CSS expression injection
        if (input.matches("(?i).*\\bexpression\\s*\\(.+")) {
            return true;
        }

        return false;
    }
}
