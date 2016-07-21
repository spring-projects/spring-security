/*
 * Copyright 2012-2016 the original author or authors.
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

package org.springframework.security.config.annotation.web;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import javax.servlet.Registration;
import javax.servlet.ServletContext;
import javax.servlet.ServletRegistration;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.runners.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.web.AbstractRequestMatcherRegistry.ServletPathValidatingtMvcRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;

/**
 * @author Rob Winch
 */
@RunWith(MockitoJUnitRunner.class)
public class AbstractRequestMatcherRegistryTests {

	@Mock
	HandlerMappingIntrospector introspector;

	ServletPathValidatingtMvcRequestMatcher matcher;

	ServletContext servletContext;

	@Before
	public void setup() {
		servletContext = spy(new MockServletContext());
		matcher = new ServletPathValidatingtMvcRequestMatcher(introspector, "/foo");
		matcher.setServletContext(servletContext);
	}

	@Test(expected = IllegalStateException.class)
	public void servletPathValidatingtMvcRequestMatcherAfterSingletonsIntantiatedFailsWithSpringServlet() {
		setMappings("/spring");
		matcher.afterSingletonsInstantiated();
	}

	@Test
	public void servletPathValidatingtMvcRequestMatcherAfterSingletonsIntantiatedWithSpringServlet() {
		matcher.setServletPath("/spring");
		setMappings("/spring");
		matcher.afterSingletonsInstantiated();
	}

	@Test
	public void servletPathValidatingtMvcRequestMatcherAfterSingletonsIntantiatedDefaultServlet() {
		setMappings("/");
		matcher.afterSingletonsInstantiated();
	}

	private void setMappings(String... mappings) {
		final ServletRegistration registration = mock(ServletRegistration.class);
		when(registration.getMappings()).thenReturn(Arrays.asList(mappings));
		Answer<Map<String, ? extends ServletRegistration>> answer = new Answer<Map<String, ? extends ServletRegistration>>() {
			@Override
			public Map<String, ? extends ServletRegistration> answer(InvocationOnMock invocation) throws Throwable {
				return Collections.<String, ServletRegistration>singletonMap("spring", registration);
			}
		};
		when(servletContext.getServletRegistrations()).thenAnswer(answer);
	}

}
