/*
 * Copyright 2002-2013 the original author or authors.
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

package org.springframework.security.web.servlet.support.csrf;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.servlet.support.RequestDataValueProcessor;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 *
 */
public class CsrfRequestDataValueProcessorTests {

	private MockHttpServletRequest request;

	private CsrfRequestDataValueProcessor processor;

	private CsrfToken token;

	private Map<String, String> expected = new HashMap<>();

	@BeforeEach
	public void setup() {
		this.request = new MockHttpServletRequest();
		this.processor = new CsrfRequestDataValueProcessor();
		this.token = new DefaultCsrfToken("1", "a", "b");
		this.request.setAttribute(CsrfToken.class.getName(), this.token);
		this.expected.put(this.token.getParameterName(), this.token.getToken());
	}

	@Test
	public void assertAllMethodsDeclared() {
		Method[] expectedMethods = ReflectionUtils.getAllDeclaredMethods(RequestDataValueProcessor.class);
		for (Method expected : expectedMethods) {
			assertThat(ReflectionUtils.findMethod(CsrfRequestDataValueProcessor.class, expected.getName(),
					expected.getParameterTypes()))
							.as("Expected to find " + expected + " defined on " + CsrfRequestDataValueProcessor.class)
							.isNotNull();
		}
	}

	@Test
	public void getExtraHiddenFieldsNoCsrfToken() {
		this.request = new MockHttpServletRequest();
		assertThat(this.processor.getExtraHiddenFields(this.request)).isEmpty();
	}

	@Test
	public void getExtraHiddenFieldsHasCsrfTokenNoMethodSet() {
		assertThat(this.processor.getExtraHiddenFields(this.request)).isEqualTo(this.expected);
	}

	@Test
	public void getExtraHiddenFieldsHasCsrfToken_GET() {
		this.processor.processAction(this.request, "action", "GET");
		assertThat(this.processor.getExtraHiddenFields(this.request)).isEmpty();
	}

	@Test
	public void getExtraHiddenFieldsHasCsrfToken_get() {
		this.processor.processAction(this.request, "action", "get");
		assertThat(this.processor.getExtraHiddenFields(this.request)).isEmpty();
	}

	@Test
	public void getExtraHiddenFieldsHasCsrfToken_POST() {
		this.processor.processAction(this.request, "action", "POST");
		assertThat(this.processor.getExtraHiddenFields(this.request)).isEqualTo(this.expected);
	}

	@Test
	public void getExtraHiddenFieldsHasCsrfToken_post() {
		this.processor.processAction(this.request, "action", "post");
		assertThat(this.processor.getExtraHiddenFields(this.request)).isEqualTo(this.expected);
	}

	@Test
	public void processAction() {
		String action = "action";
		assertThat(this.processor.processAction(this.request, action)).isEqualTo(action);
	}

	@Test
	public void processActionWithMethodArg() {
		String action = "action";
		assertThat(this.processor.processAction(this.request, action, null)).isEqualTo(action);
	}

	@Test
	public void processFormFieldValue() {
		String value = "action";
		assertThat(this.processor.processFormFieldValue(this.request, "name", value, "hidden")).isEqualTo(value);
	}

	@Test
	public void processUrl() {
		String url = "url";
		assertThat(this.processor.processUrl(this.request, url)).isEqualTo(url);
	}

	@Test
	public void createGetExtraHiddenFieldsHasCsrfToken() {
		CsrfToken token = new DefaultCsrfToken("1", "a", "b");
		this.request.setAttribute(CsrfToken.class.getName(), token);
		Map<String, String> expected = new HashMap<>();
		expected.put(token.getParameterName(), token.getToken());
		RequestDataValueProcessor processor = new CsrfRequestDataValueProcessor();
		assertThat(processor.getExtraHiddenFields(this.request)).isEqualTo(expected);
	}

}
