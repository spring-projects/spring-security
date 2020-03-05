/*
 * Copyright 2002-2020 the original author or authors.
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

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Method;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.servlet.support.RequestDataValueProcessor;

/**
 * @author Rob Winch
 *
 */
public class CsrfRequestDataValueProcessorTests {
	private MockHttpServletRequest request;

	private CsrfRequestDataValueProcessor processor;

	private CsrfToken token;

	@Before
	public void setup() {
		request = new MockHttpServletRequest();
		processor = new CsrfRequestDataValueProcessor();

		token = new DefaultCsrfToken("1", "a", "b");
		request.setAttribute(CsrfToken.class.getName(), token);
	}

	@Test
	public void assertAllMethodsDeclared() {
		Method[] expectedMethods = ReflectionUtils
				.getAllDeclaredMethods(RequestDataValueProcessor.class);
		for (Method expected : expectedMethods) {
			assertThat(
					ReflectionUtils.findMethod(CsrfRequestDataValueProcessor.class,
							expected.getName(), expected.getParameterTypes())).as(
					"Expected to find " + expected + " defined on "
							+ CsrfRequestDataValueProcessor.class).isNotNull();
		}
	}

	@Test
	public void getExtraHiddenFieldsNoCsrfToken() {
		request = new MockHttpServletRequest();
		assertThat(processor.getExtraHiddenFields(request)).isEmpty();
	}

	@Test
	public void getExtraHiddenFieldsHasCsrfTokenNoMethodSet() {
		assertThat(token.matches(processor.getExtraHiddenFields(request).getOrDefault(token.getParameterName(), null))).isTrue();
	}

	@Test
	public void getExtraHiddenFieldsHasCsrfToken_GET() {
		processor.processAction(request, "action", "GET");
		assertThat(processor.getExtraHiddenFields(request)).isEmpty();
	}

	@Test
	public void getExtraHiddenFieldsHasCsrfToken_get() {
		processor.processAction(request, "action", "get");
		assertThat(processor.getExtraHiddenFields(request)).isEmpty();
	}

	@Test
	public void getExtraHiddenFieldsHasCsrfToken_POST() {
		processor.processAction(request, "action", "POST");
		assertThat(token.matches(processor.getExtraHiddenFields(request).getOrDefault(token.getParameterName(), null))).isTrue();
	}

	@Test
	public void getExtraHiddenFieldsHasCsrfToken_post() {
		processor.processAction(request, "action", "post");
		assertThat(token.matches(processor.getExtraHiddenFields(request).getOrDefault(token.getParameterName(), null))).isTrue();
	}

	@Test
	public void processAction() {
		String action = "action";
		assertThat(processor.processAction(request, action)).isEqualTo(action);
	}

	@Test
	public void processActionWithMethodArg() {
		String action = "action";
		assertThat(processor.processAction(request, action, null)).isEqualTo(action);
	}

	@Test
	public void processFormFieldValue() {
		String value = "action";
		assertThat(processor.processFormFieldValue(request, "name", value, "hidden"))
				.isEqualTo(value);
	}

	@Test
	public void processUrl() {
		String url = "url";
		assertThat(processor.processUrl(request, url)).isEqualTo(url);
	}

	@Test
	public void createGetExtraHiddenFieldsHasCsrfToken() {
		CsrfToken token = new DefaultCsrfToken("1", "a", "b");
		request.setAttribute(CsrfToken.class.getName(), token);

		RequestDataValueProcessor processor = new CsrfRequestDataValueProcessor();
		assertThat(token.matches(processor.getExtraHiddenFields(request).getOrDefault(token.getParameterName(), null))).isTrue();
	}
}
