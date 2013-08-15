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

import org.junit.Test;

/**
 * @author Rob Winch
 *
 */
public class CsrfTokenTests {
    private final String headerName = "headerName";
    private final String parameterName = "parameterName";
    private final String tokenValue = "tokenValue";

    @Test(expected = IllegalArgumentException.class)
    public void constructorNullHeaderName() {
        new CsrfToken(null,parameterName, tokenValue);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorEmptyHeaderName() {
        new CsrfToken("",parameterName, tokenValue);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorNullParameterName() {
        new CsrfToken(headerName,null, tokenValue);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorEmptyParameterName() {
        new CsrfToken(headerName,"", tokenValue);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorNullTokenValue() {
        new CsrfToken(headerName,parameterName, null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorEmptyTokenValue() {
        new CsrfToken(headerName,parameterName, "");
    }
}
