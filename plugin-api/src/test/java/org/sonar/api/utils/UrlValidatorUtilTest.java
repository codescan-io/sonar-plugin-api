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

import static org.assertj.core.api.Assertions.assertThat;

import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

public class UrlValidatorUtilTest {

    @Test
    public void testIsUrlSafeUtil() {
        Map<String, Boolean> testUrls = new HashMap<>();
        testUrls.put("https://w3schools.com/api/data", Boolean.TRUE);
        testUrls.put("http://twitch.tv/path?query=v", Boolean.TRUE);
        testUrls.put("http://docs.google.com", Boolean.TRUE);
        testUrls.put("https://192.168.1.1/admin", Boolean.FALSE);         	// Private IP (blocked)
        testUrls.put("ftp://sharma.com/files", Boolean.FALSE);           	// Disallowed protocol
        testUrls.put("http://2130706433/admin", Boolean.FALSE);             // URL with localhost redirect
        testUrls.put("http://127.0.0.1:8080/", Boolean.FALSE);            	// Localhost (blocked)
        testUrls.put("http://[::ffff:127.0.0.1]/api", Boolean.FALSE);
        testUrls.put("http://ftcn4f7jqjfc6b4e56o9azx68xes2iq7.oastify.com/", Boolean.TRUE);
        testUrls.put("http://0x7f.0x00.0x00.0x01/root", Boolean.FALSE);
        testUrls.put("http://youtube.com@internal-server/path", Boolean.FALSE);
        testUrls.put(null, Boolean.TRUE);

        for (String url : testUrls.keySet()) {
            boolean valid = UrlValidatorUtil.isUrlValid(url);
            boolean expected = testUrls.get(url);
            assertThat(valid)
                    .withFailMessage(url + " failed test, expected:" + expected + " | actual:" + valid)
                    .isEqualTo(expected);
        }
    }

    @Test
    public void testIsTextWithUrlSafeUtil() {
        Map<String, Boolean> texts = new HashMap<>();
        texts.put("This is a description. This shouldn't affect the output. https://uber.com/api/data", Boolean.TRUE);            	// Localhost (blocked)
        texts.put("The description can contain <a href=https://google.com/> and other links. Check if this is valid? http://127.0.0.1:8080/", Boolean.FALSE);            	// Localhost (blocked)
        texts.put("No URLs here!", Boolean.TRUE);
        texts.put(null, Boolean.TRUE);

        for (String text : texts.keySet()) {
            boolean valid = UrlValidatorUtil.textContainsValidUrl(text);
            boolean expected = texts.get(text);
            assertThat(valid)
                    .withFailMessage(text + " failed test, expected:" + expected + " | actual:" + valid)
                    .isEqualTo(expected);
        }
    }

    @Test
    public void testSanitizerUtil() {
        Map<String, String> texts = new HashMap<>();
        texts.put("https://uber.com/path?foo=bar", "https://uber.com/path?foo=bar");
        texts.put("  javascript:alert('XSS')  ", null);
        texts.put("http://microsoft.com/%3Cscript%3Ealert(1)%3C/script%3E", "http://microsoft.com/");
        texts.put("data:text/html,<script>alert('xss')</script>", null);
        texts.put("https://safe.com/path?onerror=alert(1)", "https://safe.com/path?alert(1)");
        texts.put("><img src=X onerror=confirm(1)>", null);
        texts.put("ftp://facebook.com/resource", null);
        texts.put(null, null);

        for (String text : texts.keySet()) {
            String sanitized = UrlValidatorUtil.sanitizeUrl(text);
            String expected = texts.get(text);
            assertThat(sanitized)
                    .withFailMessage(text + " failed test, expected:" + expected + " | actual:" + sanitized)
                    .isEqualTo(expected);
        }
    }
}
