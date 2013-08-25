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

import static org.fest.assertions.Assertions.assertThat;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;

/**
 * @author Rob Winch
 *
 */
public class CsrfRequestDataValueProcessorTests {
    private MockHttpServletRequest request;

    private MockHttpServletResponse response;

    private CsrfRequestDataValueProcessor processor;

    @Before
    public void setup() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        processor = new CsrfRequestDataValueProcessor();
    }

    @Test
    public void getExtraHiddenFieldsNoCsrfToken() {
        assertThat(processor.getExtraHiddenFields(request)).isEmpty();
    }

    @Test
    public void getExtraHiddenFieldsHasCsrfToken() {
        CsrfToken token = new DefaultCsrfToken("1", "a", "b");
        request.setAttribute(CsrfToken.class.getName(), token);
        Map<String,String> expected = new HashMap<String,String>();
        expected.put(token.getParameterName(),token.getToken());

        assertThat(processor.getExtraHiddenFields(request)).isEqualTo(expected);
    }

    @Test
    public void processAction() {
        String action = "action";
        assertThat(processor.processAction(request, action)).isEqualTo(action);
    }

    @Test
    public void processFormFieldValue() {
        String value = "action";
        assertThat(processor.processFormFieldValue(request, "name", value, "hidden")).isEqualTo(value);
    }

    @Test
    public void processUrl() {
        String url = "url";
        assertThat(processor.processUrl(request, url)).isEqualTo(url);
    }
}
