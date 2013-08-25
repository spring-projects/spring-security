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

import static org.fest.assertions.Assertions.assertThat;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * @author Rob Winch
 *
 */
public class HttpSessionCsrfTokenRepositoryTests {
    private MockHttpServletRequest request;

    private MockHttpServletResponse response;

    private CsrfToken token;
    private HttpSessionCsrfTokenRepository repo;

    @Before
    public void setup() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        repo = new HttpSessionCsrfTokenRepository();
    }

    @Test
    public void generateToken() {
        token = repo.generateToken(request);

        assertThat(token.getParameterName()).isEqualTo("_csrf");
        assertThat(token.getToken()).isNotEmpty();

        CsrfToken loadedToken = repo.loadToken(request);

        assertThat(loadedToken).isNull();
    }

    @Test
    public void generateCustomParameter() {
        String paramName = "_csrf";
        repo.setParameterName(paramName);

        token = repo.generateToken(request);

        assertThat(token.getParameterName()).isEqualTo(paramName);
        assertThat(token.getToken()).isNotEmpty();
    }

    @Test
    public void loadTokenNull() {
        assertThat(repo.loadToken(request)).isNull();
    }

    @Test
    public void saveToken() {
        CsrfToken tokenToSave = new DefaultCsrfToken("123", "abc", "def");
        repo.saveToken(tokenToSave, request, response);

        String attrName = request.getSession().getAttributeNames()
                .nextElement();
        CsrfToken loadedToken = (CsrfToken) request.getSession().getAttribute(
                attrName);

        assertThat(loadedToken).isEqualTo(tokenToSave);
    }

    @Test
    public void saveTokenCustomSessionAttribute() {
        CsrfToken tokenToSave = new DefaultCsrfToken("123", "abc", "def");
        String sessionAttributeName = "custom";
        repo.setSessionAttributeName(sessionAttributeName);
        repo.saveToken(tokenToSave, request, response);

        CsrfToken loadedToken = (CsrfToken) request.getSession().getAttribute(
                sessionAttributeName);

        assertThat(loadedToken).isEqualTo(tokenToSave);
    }

    @Test
    public void saveTokenNullToken() {
        saveToken();

        repo.saveToken(null, request, response);

        assertThat(request.getSession().getAttributeNames().hasMoreElements())
                .isFalse();
    }

    @Test(expected = IllegalArgumentException.class)
    public void setSessionAttributeNameEmpty() {
        repo.setSessionAttributeName("");
    }

    @Test(expected = IllegalArgumentException.class)
    public void setSessionAttributeNameNull() {
        repo.setSessionAttributeName(null);
    }

    @Test(expected = IllegalArgumentException.class)
    public void setParameterNameEmpty() {
        repo.setParameterName("");
    }

    @Test(expected = IllegalArgumentException.class)
    public void setParameterNameNull() {
        repo.setParameterName(null);
    }
}
