/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.util;

import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.springframework.util.Assert;

/**
 * Servlet API-related methods.
 * 
 * @author Valery Tydykov
 * 
 */
public final class ServletUtils {
    /**
     * This is a static class that should not be instantiated.
     */
    private ServletUtils() throws InstantiationException {
    }

    public static Map extractHeaderValues(HttpServletRequest request, List keys) {
        Assert.notNull(request);
        Assert.notNull(keys);

        final Map headerValues = new HashMap();
        // for each header name/value
        for (Enumeration en = request.getHeaderNames(); en.hasMoreElements();) {
            String key = (String) en.nextElement();

            if (keys.contains(key)) {
                // found key in the list of the keys to return
                String value = request.getHeader(key);
                headerValues.put(key, value);
            }
        }

        return headerValues;
    }

    public static Map extractCookiesValues(HttpServletRequest request, List keys) {
        Assert.notNull(request);
        Assert.notNull(keys);

        final Map cookiesValues = new HashMap();
        final Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            // for each cookie
            for (int i = 0; i < cookies.length; i++) {
                String key = cookies[i].getName();

                if (keys.contains(key)) {
                    // found key in the list of the keys to return
                    String value = cookies[i].getValue();
                    cookiesValues.put(key, value);
                }
            }
        }

        return cookiesValues;
    }

    public static String findCookieValue(final HttpServletRequest request, final String key) {
        Assert.notNull(request);

        String value = null;
        final Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            // find cookie key
            for (int i = 0; i < cookies.length; i++) {
                if (StringUtils.notNull(cookies[i].getName()).equals(key)) {
                    // cookie key found
                    value = cookies[i].getValue();
                    break;
                }
            }
        }

        return value;
    }
}
