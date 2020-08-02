/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.test.web.servlet.setup;

import javax.servlet.Filter;
import javax.servlet.ServletContext;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.security.config.BeanIds;
import org.springframework.test.web.servlet.setup.ConfigurableMockMvcBuilder;
import org.springframework.web.context.WebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

@RunWith(MockitoJUnitRunner.class)
public class SecurityMockMvcConfigurerTests {

	@Mock
	private Filter filter;

	@Mock
	private Filter beanFilter;

	@Mock
	private ConfigurableMockMvcBuilder<?> builder;

	@Mock
	private WebApplicationContext context;

	@Mock
	private ServletContext servletContext;

	@Before
	public void setup() {
		given(this.context.getServletContext()).willReturn(this.servletContext);
	}

	@Test
	public void beforeMockMvcCreatedOverrideBean() throws Exception {
		returnFilterBean();
		SecurityMockMvcConfigurer configurer = new SecurityMockMvcConfigurer(this.filter);
		configurer.afterConfigurerAdded(this.builder);
		configurer.beforeMockMvcCreated(this.builder, this.context);
		assertFilterAdded(this.filter);
		verify(this.servletContext).setAttribute(BeanIds.SPRING_SECURITY_FILTER_CHAIN, this.filter);
	}

	@Test
	public void beforeMockMvcCreatedBean() throws Exception {
		returnFilterBean();
		SecurityMockMvcConfigurer configurer = new SecurityMockMvcConfigurer();
		configurer.afterConfigurerAdded(this.builder);
		configurer.beforeMockMvcCreated(this.builder, this.context);
		assertFilterAdded(this.beanFilter);
	}

	@Test
	public void beforeMockMvcCreatedNoBean() throws Exception {
		SecurityMockMvcConfigurer configurer = new SecurityMockMvcConfigurer(this.filter);
		configurer.afterConfigurerAdded(this.builder);
		configurer.beforeMockMvcCreated(this.builder, this.context);
		assertFilterAdded(this.filter);
	}

	@Test(expected = IllegalStateException.class)
	public void beforeMockMvcCreatedNoFilter() {
		SecurityMockMvcConfigurer configurer = new SecurityMockMvcConfigurer();
		configurer.afterConfigurerAdded(this.builder);
		configurer.beforeMockMvcCreated(this.builder, this.context);
	}

	private void assertFilterAdded(Filter filter) {
		ArgumentCaptor<SecurityMockMvcConfigurer.DelegateFilter> filterArg = ArgumentCaptor
				.forClass(SecurityMockMvcConfigurer.DelegateFilter.class);
		verify(this.builder).addFilters(filterArg.capture());
		assertThat(filterArg.getValue().getDelegate()).isEqualTo(filter);
	}

	private void returnFilterBean() {
		given(this.context.containsBean(anyString())).willReturn(true);
		given(this.context.getBean(anyString(), eq(Filter.class))).willReturn(this.beanFilter);
	}

}
