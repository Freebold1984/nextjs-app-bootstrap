package com.xssdetector;

import java.util.regex.Pattern;
import java.util.List;
import java.util.Arrays;

public class DOMAnalyzer {
    private static final List<String> DOM_XSS_SINKS = Arrays.asList(
        "innerHTML",
        "outerHTML",
        "document.write",
        "document.writeln",
        "eval",
        "setTimeout",
        "setInterval",
        "execScript",
        "Function",
        "location",
        "location.href",
        "location.replace",
        "location.assign",
        "element.src",
        "element.setAttribute",
        "element.data",
        "element.codebase",
        "element.baseURI"
    );

    private static final List<String> DOM_XSS_SOURCES = Arrays.asList(
        "document.URL",
        "document.documentURI",
        "document.URLUnencoded",
        "document.baseURI",
        "location",
        "location.href",
        "location.search",
        "location.hash",
        "location.pathname",
        "document.referrer",
        "window.name",
        "history.pushState",
        "history.replaceState",
        "localStorage",
        "sessionStorage"
    );

    private static final Pattern SCRIPT_CONTEXT_PATTERN = Pattern.compile(
        "<script[^>]*>([\\s\\S]*?)</script>",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern EVENT_HANDLER_PATTERN = Pattern.compile(
        "on\\w+\\s*=\\s*['\"]([^'\"]*)['\"]",
        Pattern.CASE_INSENSITIVE
    );

    public boolean analyzeForDOMXSS(String input) {
        // Check for direct sink usage
        for (String sink : DOM_XSS_SINKS) {
            if (input.toLowerCase().contains(sink.toLowerCase())) {
                return true;
            }
        }

        // Check for source + sink combinations
        for (String source : DOM_XSS_SOURCES) {
            if (input.toLowerCase().contains(source.toLowerCase())) {
                for (String sink : DOM_XSS_SINKS) {
                    if (input.toLowerCase().contains(sink.toLowerCase())) {
                        return true;
                    }
                }
            }
        }

        // Check script context
        var scriptMatcher = SCRIPT_CONTEXT_PATTERN.matcher(input);
        while (scriptMatcher.find()) {
            String scriptContent = scriptMatcher.group(1);
            if (containsUnsafeJavaScript(scriptContent)) {
                return true;
            }
        }

        // Check event handlers
        var eventMatcher = EVENT_HANDLER_PATTERN.matcher(input);
        while (eventMatcher.find()) {
            String eventContent = eventMatcher.group(1);
            if (containsUnsafeJavaScript(eventContent)) {
                return true;
            }
        }

        return false;
    }

    private boolean containsUnsafeJavaScript(String content) {
        // Check for dynamic code execution
        if (content.contains("eval(") || content.contains("new Function(")) {
            return true;
        }

        // Check for dangerous DOM modifications
        if (content.contains("innerHTML") || content.contains("outerHTML")) {
            return true;
        }

        // Check for dangerous redirects
        if (content.contains("location.href") || content.contains("location.replace")) {
            return true;
        }

        // Check for data URI scheme
        if (content.contains("data:text/html") || content.contains("javascript:")) {
            return true;
        }

        return false;
    }
}
