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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.runners.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import javax.servlet.ServletContext;
import javax.servlet.ServletRegistration;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import static org.mockito.Mockito.*;

/**
 * @author Rob Winch
 */
@RunWith(MockitoJUnitRunner.class)
public class AbstractRequestMatcherRegistryTests {

	@Mock
	HandlerMappingIntrospector introspector;

	MvcRequestMatcher matcher;

	ServletContext servletContext;

	@Before
	public void setup() {
		servletContext = spy(new MockServletContext());
		matcher = new MvcRequestMatcher(introspector, "/foo");
		matcher.setServletContext(servletContext);
	}

	@Test(expected = IllegalStateException.class)
	public void servletPathValidatingMvcRequestMatcherAfterPropertiesSetFailsWithSpringServlet() throws Exception {
		setMappings("/spring");
		matcher.afterPropertiesSet();
	}

	@Test
	public void servletPathValidatingMvcRequestMatcherAfterPropertiesSetWithSpringServlet() throws Exception {
		matcher.setServletPath("/spring");
		setMappings("/spring");
		matcher.afterPropertiesSet();
	}

	@Test
	public void servletPathValidatingMvcRequestMatcherAfterPropertiesSetDefaultServlet() throws Exception {
		setMappings("/");
		matcher.afterPropertiesSet();
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
