/*
 * Copyright 2002-2017 the original author or authors.
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

package org.springframework.security.web.reactive.result.view;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;

import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.web.server.csrf.CsrfToken;
import org.springframework.security.web.server.csrf.DefaultCsrfToken;
import org.springframework.util.ReflectionUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class CsrfRequestDataValueProcessorTests {

	private MockServerWebExchange exchange = exchange(HttpMethod.GET);

	private CsrfRequestDataValueProcessor processor = new CsrfRequestDataValueProcessor();

	private CsrfToken token = new DefaultCsrfToken("1", "a", "b");

	private Map<String, String> expected = new HashMap<>();

	@Before
	public void setup() {
		this.expected.put(this.token.getParameterName(), this.token.getToken());
		this.exchange.getAttributes().put(CsrfRequestDataValueProcessor.DEFAULT_CSRF_ATTR_NAME, this.token);
	}

	@Test
	public void assertAllMethodsDeclared() {
		Method[] expectedMethods = ReflectionUtils.getAllDeclaredMethods(CsrfRequestDataValueProcessor.class);
		for (Method expected : expectedMethods) {
			assertThat(ReflectionUtils.findMethod(CsrfRequestDataValueProcessor.class, expected.getName(),
					expected.getParameterTypes()))
							.as("Expected to find " + expected + " defined on " + CsrfRequestDataValueProcessor.class)
							.isNotNull();
		}
	}

	@Test
	public void getExtraHiddenFieldsNoCsrfToken() {
		this.exchange.getAttributes().clear();
		assertThat(this.processor.getExtraHiddenFields(this.exchange)).isEmpty();
	}

	@Test
	public void getExtraHiddenFieldsHasCsrfTokenNoMethodSet() {
		assertThat(this.processor.getExtraHiddenFields(this.exchange)).isEqualTo(this.expected);
	}

	@Test
	public void getExtraHiddenFieldsHasCsrfToken_GET() {
		this.processor.processAction(this.exchange, "action", "GET");
		assertThat(this.processor.getExtraHiddenFields(this.exchange)).isEmpty();
	}

	@Test
	public void getExtraHiddenFieldsHasCsrfToken_get() {
		this.processor.processAction(this.exchange, "action", "get");
		assertThat(this.processor.getExtraHiddenFields(this.exchange)).isEmpty();
	}

	@Test
	public void getExtraHiddenFieldsHasCsrfToken_POST() {
		this.processor.processAction(this.exchange, "action", "POST");
		assertThat(this.processor.getExtraHiddenFields(this.exchange)).isEqualTo(this.expected);
	}

	@Test
	public void getExtraHiddenFieldsHasCsrfToken_post() {
		this.processor.processAction(this.exchange, "action", "post");
		assertThat(this.processor.getExtraHiddenFields(this.exchange)).isEqualTo(this.expected);
	}

	@Test
	public void processActionWithMethodArg() {
		String action = "action";
		assertThat(this.processor.processAction(this.exchange, action, null)).isEqualTo(action);
	}

	@Test
	public void processFormFieldValue() {
		String value = "action";
		assertThat(this.processor.processFormFieldValue(this.exchange, "name", value, "hidden")).isEqualTo(value);
	}

	@Test
	public void processUrl() {
		String url = "url";
		assertThat(this.processor.processUrl(this.exchange, url)).isEqualTo(url);
	}

	@Test
	public void createGetExtraHiddenFieldsHasCsrfToken() {
		CsrfToken token = new DefaultCsrfToken("1", "a", "b");
		this.exchange.getAttributes().put(CsrfRequestDataValueProcessor.DEFAULT_CSRF_ATTR_NAME, token);
		Map<String, String> expected = new HashMap<>();
		expected.put(token.getParameterName(), token.getToken());
		CsrfRequestDataValueProcessor processor = new CsrfRequestDataValueProcessor();
		assertThat(this.processor.getExtraHiddenFields(this.exchange)).isEqualTo(expected);
	}

	private MockServerWebExchange exchange(HttpMethod method) {
		return MockServerWebExchange.from(MockServerHttpRequest.method(HttpMethod.GET, "/"));
	}

}
