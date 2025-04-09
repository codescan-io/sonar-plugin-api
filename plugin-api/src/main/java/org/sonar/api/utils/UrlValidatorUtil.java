/*
 * Sonar Plugin API
 * Copyright (C) 2009-2024 SonarSource SA
 * mailto:info AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.sonar.api.utils;

import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.URLDecoder;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;
import org.apache.commons.lang3.StringUtils;

public class UrlValidatorUtil {

    // List of allowed protocols
    private static final List<String> ALLOWED_PROTOCOLS = Arrays.asList("http", "https");
    private static final List<String> PROTOCOLS = Arrays.asList("http", "https", "ftp", "file", "gopher", "ldap");
    private static final List<String> BLOCKED_EXTENSIONS = Arrays.asList(".js", ".cjs", ".mjs", ".xhtm", ".htm");

    // List of blocked IP address patterns
    private static final List<Pattern> BLOCKED_IP_PATTERNS = Arrays.asList(
            // Private IP ranges
            Pattern.compile("^10\\..*"),                      // 10.0.0.0/8
            Pattern.compile("^172\\.(1[6-9]|2[0-9]|3[0-1])\\..*"), // 172.16.0.0/12
            Pattern.compile("^192\\.168\\..*"),               // 192.168.0.0/16
            // Localhost
            Pattern.compile("^127\\..*"),                     // 127.0.0.0/8
            Pattern.compile("^0\\.0\\.0\\.0$"),
            // Link-local addresses
            Pattern.compile("^169\\.254\\..*"),               // 169.254.0.0/16
            // Loop-back in IPv6
            Pattern.compile("^::1$"),
            Pattern.compile("^[fF][cCdD]00:.*"),              // fc00::/7 (unique local addresses)
            Pattern.compile("^[fF][eE]80:.*")                 // fe80::/10 (link-local addresses)
    );

    // Pattern to extract URLs from text - Modified to support any protocol
    private static final Pattern MALICIOUS_PATTERN = Pattern.compile(
            "(?i)(javascript:|data:text/html|vbscript:|<script.*?>.*?</script>|<.*?>|on\\w+\\s*=|%3C|%3E|%22|%27|\\\"|\\'|\\s+)",
            Pattern.CASE_INSENSITIVE
    );

    // List of common SSRF bypass attempts in hostname
    private static final List<String> SUSPICIOUS_KEYWORDS = Arrays.asList(
            "@", "\\", "#", "localhost", "127.0.0.1", "0.0.0.0", "::1", "0177.0.0.1",
            "0x7f.0.0.1", "2130706433", "0x7f", "0x0000007f", "0x00", "0x00000000", "0x00000001"
    );

    // Pattern to extract URLs from text

    /**
     * Checks if a text contains any invalid URLs
     * Returns true only if all URLs in the text are valid
     * Stops processing at the first invalid URL
     *
     * @param content the text content that may contain URLs
     * @return boolean - true if all URLs are valid, false if any URL is invalid
     */
    public static boolean textContainsValidUrl(String content) {
        if (content == null || content.trim().isEmpty()) {
            return true; // No content to check
        }

        String[] words = content.split("\\s+");
        for (String word : words) {
            // Skip words that are definitely not URLs
            if (word.length() < 3)
                continue; // "ftp" is 3 chars
            word = word.replaceAll("[,.!?;:'\")]$", "");
            for (String protocol : PROTOCOLS) {
                if (word.toLowerCase().startsWith(protocol)) {
                    if (!isUrlValid(word)) {
                        return false;
                    }
                    break; // URL was valid, no need to check other protocols
                }
            }
        }

        return true;
    }

    /**
     * Validates a URL to prevent SSRF attacks
     *
     * @param inputUrl the URL to validate
     * @return boolean - true if valid, false if invalid
     */
    public static boolean isUrlValid(String inputUrl) {
        if (inputUrl == null || inputUrl.trim().isEmpty()) {
            return true;
        }

        // Basic URL validation
        URL url;
        try {
            url = new URL(inputUrl);
        } catch (MalformedURLException e) {
            return false;
        }

        // Check protocol
        String protocol = url.getProtocol().toLowerCase();
        if (!ALLOWED_PROTOCOLS.contains(protocol)) {
            return false;
        }

        // Get hostname
        String host = url.getHost().toLowerCase();
        if (checkIfInvalidIpAddress(host)) return false;

        // Check for suspicious keywords in URL
        for (String keyword : SUSPICIOUS_KEYWORDS) {
            if (inputUrl.toLowerCase().contains(keyword)) {
                return false;
            }
        }

        // Check for blocked extensions in URL
        for (String keyword : BLOCKED_EXTENSIONS) {
            if (inputUrl.toLowerCase().contains(keyword)) {
                return false;
            }
        }

        // Initiate DNS resolution
        try {
            InetAddress inetAddress = InetAddress.getByName(host);
            if (checkIfInvalidIpAddress(inetAddress.getHostAddress())) return false;
        } catch (UnknownHostException e) {
            return false;
        }

        return true;
    }

    private static boolean checkIfInvalidIpAddress(String ipAddress) {
        // Check if it's an IP address and if it's in a blocked range
        return isIpAddress(ipAddress) && isBlockedIpAddress(ipAddress);
    }

    public static String sanitizeUrl(String url) {
        if (StringUtils.isBlank(url) || !isUrlValid(url)) return null;

        String decoded = decodeUrl(url.trim());
        String cleaned = MALICIOUS_PATTERN.matcher(decoded).replaceAll("");

        // Step 3: Try to parse the URI to normalize and validate it
        try {
            URI uri = new URI(cleaned);
            String scheme = uri.getScheme();

            // Default to https if no scheme or invalid scheme
            if (scheme == null || (!ALLOWED_PROTOCOLS.contains(scheme))) {
                cleaned = "https://" + cleaned.replaceAll("^.*?://", "");
            }

            // Rebuild URI (safe version)
            URI safeUri = new URI(cleaned);
            return safeUri.toString();
        } catch (URISyntaxException e) {
            // If parsing fails, just return the cleaned string as-is
            return cleaned;
        }
    }

    /**
     * Simple check if a host is an IP address
     */
    private static boolean isIpAddress(String host) {
        // Simple IPv4 validation
        if (host.matches("^\\d+\\.\\d+\\.\\d+\\.\\d+$")) {
            return true;
        }
        // Basic IPv6 validation (simplified)
        return host.contains(":");
    }

    /**
     * Check if an IP address is in a blocked range
     */
    private static boolean isBlockedIpAddress(String ipAddress) {
        for (Pattern pattern : BLOCKED_IP_PATTERNS) {
            if (pattern.matcher(ipAddress).find()) {
                return true;
            }
        }
        return false;
    }

    private static String decodeUrl(String input) {
        try {
            String prev;
            String decoded = input;
            do {
                prev = decoded;
                decoded = URLDecoder.decode(decoded, "UTF-8");
            } while (!decoded.equals(prev));
            return decoded;
        } catch (UnsupportedEncodingException e) {
            return input;
        }
    }
}