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

import static org.mockito.Mockito.verify;

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

    @Before
    public void setup() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        strategy = new CsrfAuthenticationStrategy(csrfTokenRepository);
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorNullCsrfTokenRepository() {
        new CsrfAuthenticationStrategy(null);
    }

    @Test
    public void logoutRemovesCsrfToken() {
        strategy.onAuthentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"),request, response);

        verify(csrfTokenRepository).saveToken(null, request, response);
    }

}

