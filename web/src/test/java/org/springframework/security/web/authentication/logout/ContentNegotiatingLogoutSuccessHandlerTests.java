/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.web.authentication.logout;

import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;

import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.*;

/**
 * Test for ContentNegotiatingLogoutSuccessHandler
 *
 * @author Shazin Sadakath
 */
public class ContentNegotiatingLogoutSuccessHandlerTests {

    @Test
    public void requestFromAjax() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        request.addHeader("HTTP_X_REQUESTED_WITH", "XMLHttpRequest");
        ContentNegotiatingLogoutSuccessHandler handler = new ContentNegotiatingLogoutSuccessHandler();
        handler.onLogoutSuccess(request, response, mock(Authentication.class));

        assertThat(response.getStatus()).isEqualTo(HttpStatus.NO_CONTENT.value());
    }

    @Test
    public void requestFromBrowser() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        MockHttpServletResponse response = new MockHttpServletResponse();
        ContentNegotiatingLogoutSuccessHandler handler = new ContentNegotiatingLogoutSuccessHandler();
        handler.onLogoutSuccess(request, response, mock(Authentication.class));

        assertThat(response.getStatus()).isEqualTo(HttpStatus.FOUND.value());
    }
}
