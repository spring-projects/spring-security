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
package org.springframework.security.test.web.servlet.setup;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.test.web.servlet.setup.ConfigurableMockMvcBuilder;
import org.springframework.web.context.WebApplicationContext;

import javax.servlet.Filter;

import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class SecurityMockMvcConfigurerTests {
	@Mock
	private Filter filter;
	@Mock
	private Filter beanFilter;
	@Mock
	private ConfigurableMockMvcBuilder builder;
	@Mock
	private WebApplicationContext context;

	@Test
	public void beforeMockMvcCreatedOverrideBean() throws Exception {
		returnFilterBean();
		SecurityMockMvcConfigurer configurer = new SecurityMockMvcConfigurer(filter);

		configurer.beforeMockMvcCreated(builder, context);

		verify(builder).addFilters(filter);
	}

	@Test
	public void beforeMockMvcCreatedBean() throws Exception {
		returnFilterBean();
		SecurityMockMvcConfigurer configurer = new SecurityMockMvcConfigurer();

		configurer.beforeMockMvcCreated(builder, context);

		verify(builder).addFilters(beanFilter);
	}

	@Test
	public void beforeMockMvcCreatedNoBean() throws Exception {
		SecurityMockMvcConfigurer configurer = new SecurityMockMvcConfigurer(filter);

		configurer.beforeMockMvcCreated(builder, context);

		verify(builder).addFilters(filter);
	}

	@Test(expected = IllegalStateException.class)
	public void beforeMockMvcCreatedNoFilter() throws Exception {
		SecurityMockMvcConfigurer configurer = new SecurityMockMvcConfigurer();

		configurer.beforeMockMvcCreated(builder, context);
	}

	private void returnFilterBean() {
		when(context.containsBean(anyString())).thenReturn(true);
		when(context.getBean(anyString(), eq(Filter.class))).thenReturn(beanFilter);
	}
}