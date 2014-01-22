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

import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;

/**
 * @author Rob Winch
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class CsrfAuthenticationStrategyTests {
    @Mock
    private CsrfTokenRepository csrfTokenRepository;

    private MockHttpServletRequest request;

    private MockHttpServletResponse response;

    private CsrfAuthenticationStrategy strategy;

    private CsrfToken existingToken;

    private CsrfToken generatedToken;

    @Before
    public void setup() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        strategy = new CsrfAuthenticationStrategy(csrfTokenRepository);
        existingToken = new DefaultCsrfToken("_csrf", "_csrf", "1");
        generatedToken = new DefaultCsrfToken("_csrf", "_csrf", "2");
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorNullCsrfTokenRepository() {
        new CsrfAuthenticationStrategy(null);
    }

    @Test
    public void logoutRemovesCsrfTokenAndSavesNew() {
        when(csrfTokenRepository.loadToken(request)).thenReturn(existingToken);
        when(csrfTokenRepository.generateToken(request)).thenReturn(generatedToken);
        strategy.onAuthentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"), request, response);

        verify(csrfTokenRepository).saveToken(null, request, response);
        // SEC-2404
        verify(csrfTokenRepository).saveToken(eq(generatedToken), eq(request), eq(response));
    }

    @Test
    public void logoutRemovesNoActionIfNullToken() {
        strategy.onAuthentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"), request, response);

        verify(csrfTokenRepository,never()).saveToken(any(CsrfToken.class), any(HttpServletRequest.class), any(HttpServletResponse.class));
    }
}

