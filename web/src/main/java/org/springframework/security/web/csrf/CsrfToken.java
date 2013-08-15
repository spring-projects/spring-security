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
package org.springframework.security.web.csrf;

import java.io.Serializable;

import org.springframework.util.Assert;

/**
 * A CSRF token that is used to protect against CSRF attacks.
 *
 * @author Rob Winch
 * @since 3.2
 */
@SuppressWarnings("serial")
public final class CsrfToken implements Serializable {

    private final String token;

    private final String parameterName;

    private final String headerName;

    /**
     * Creates a new instance
     * @param headerName the HTTP header name to use
     * @param parameterName the HTTP parameter name to use
     * @param token the value of the token (i.e. expected value of the HTTP parameter of parametername).
     */
    public CsrfToken(String headerName, String parameterName, String token) {
        Assert.hasLength(headerName, "headerName cannot be null or empty");
        Assert.hasLength(parameterName, "parameterName cannot be null or empty");
        Assert.hasLength(token, "token cannot be null or empty");
        this.headerName = headerName;
        this.parameterName = parameterName;
        this.token = token;
    }

    /**
     * Gets the HTTP header that the CSRF is populated on the response and can
     * be placed on requests instead of the parameter. Cannot be null.
     *
     * @return the HTTP header that the CSRF is populated on the response and
     *         can be placed on requests instead of the parameter
     */
    public String getHeaderName() {
        return headerName;
    }

    /**
     * Gets the HTTP parameter name that should contain the token. Cannot be null.
     * @return the HTTP parameter name that should contain the token.
     */
    public String getParameterName() {
        return parameterName;
    }

    /**
     * Gets the token value. Cannot be null.
     * @return the token value
     */
    public String getToken() {
        return token;
    }
}
