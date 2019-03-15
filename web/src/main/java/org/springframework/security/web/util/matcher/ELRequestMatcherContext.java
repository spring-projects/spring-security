/*
 * Copyright 2009 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.util.matcher;


import javax.servlet.http.HttpServletRequest;

import org.springframework.util.StringUtils;

class ELRequestMatcherContext {

    private final HttpServletRequest request;

    public ELRequestMatcherContext(HttpServletRequest request) {
        this.request = request;
    }

    public boolean hasIpAddress(String ipAddress) {
        return (new IpAddressMatcher(ipAddress).matches(request));
    }

    public boolean hasHeader(String headerName, String value) {
        String header = request.getHeader(headerName);
        if (!StringUtils.hasText(header)) {
            return false;
        }

        if (header.contains(value)) {
            return true;
        }

        return false;
    }

}
