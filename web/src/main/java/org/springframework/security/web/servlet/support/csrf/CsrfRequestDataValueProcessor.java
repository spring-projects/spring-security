/*
 * Copyright 2002-2013 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.servlet.support.csrf;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.servlet.support.RequestDataValueProcessor;

/**
 * Integration with Spring Web MVC that automatically adds the {@link CsrfToken}
 * into forms with hidden inputs when using Spring tag libraries.
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class CsrfRequestDataValueProcessor implements
        RequestDataValueProcessor {

    /*
     * (non-Javadoc)
     *
     * @see org.springframework.web.servlet.support.RequestDataValueProcessor#
     * processAction(javax.servlet.http.HttpServletRequest, java.lang.String)
     */
    public String processAction(HttpServletRequest request, String action) {
        return action;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.springframework.web.servlet.support.RequestDataValueProcessor#
     * processFormFieldValue(javax.servlet.http.HttpServletRequest,
     * java.lang.String, java.lang.String, java.lang.String)
     */
    public String processFormFieldValue(HttpServletRequest request,
            String name, String value, String type) {
        return value;
    }

    /*
     * (non-Javadoc)
     *
     * @see org.springframework.web.servlet.support.RequestDataValueProcessor#
     * getExtraHiddenFields(javax.servlet.http.HttpServletRequest)
     */
    public Map<String, String> getExtraHiddenFields(HttpServletRequest request) {
        CsrfToken token = (CsrfToken) request.getAttribute(CsrfToken.class
                .getName());
        if (token == null) {
            return Collections.emptyMap();
        }
        Map<String, String> hiddenFields = new HashMap<String, String>(1);
        hiddenFields.put(token.getParameterName(), token.getToken());
        return hiddenFields;
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * org.springframework.web.servlet.support.RequestDataValueProcessor#processUrl
     * (javax.servlet.http.HttpServletRequest, java.lang.String)
     */
    public String processUrl(HttpServletRequest request, String url) {
        return url;
    }
}
