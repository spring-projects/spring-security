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

package org.springframework.security.config.test;

import org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.util.InMemoryXmlWebApplicationContext;
import org.springframework.test.context.web.GenericXmlWebContextLoader;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.setup.ConfigurableMockMvcBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.test.web.servlet.setup.MockMvcConfigurer;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.context.support.XmlWebApplicationContext;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import static org.springframework.security.config.BeanIds.SPRING_SECURITY_FILTER_CHAIN;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class SpringTestContext implements Closeable {
	private Object test;

	private ConfigurableWebApplicationContext context;

	private List<Filter> filters = new ArrayList<>();

	public void setTest(Object test) {
		this.test = test;
	}

	@Override
	public void close() throws IOException {
		try {
			this.context.close();
		} catch(Exception e) {}
	}

	public SpringTestContext context(ConfigurableWebApplicationContext context) {
		this.context = context;
		return this;
	}

	public SpringTestContext register(Class<?>... classes) {
		AnnotationConfigWebApplicationContext applicationContext = new AnnotationConfigWebApplicationContext();
		applicationContext.register(classes);
		this.context = applicationContext;
		return this;
	}

	public SpringTestContext testConfigLocations(String... configLocations) {
		GenericXmlWebContextLoader loader = new GenericXmlWebContextLoader();
		String[] locations = loader.processLocations(this.test.getClass(),
			configLocations);
		return configLocations(locations);
	}

	public SpringTestContext configLocations(String... configLocations) {
		XmlWebApplicationContext context = new XmlWebApplicationContext();
		context.setConfigLocations(configLocations);
		this.context = context;
		return this;
	}

	public SpringTestContext context(String configuration) {
		InMemoryXmlWebApplicationContext context = new InMemoryXmlWebApplicationContext(configuration);
		this.context = context;
		return this;
	}

	public SpringTestContext mockMvcAfterSpringSecurityOk() {
		return addFilter(new OncePerRequestFilter() {
			@Override
			protected void doFilterInternal(HttpServletRequest request,
				HttpServletResponse response, FilterChain filterChain)
				throws ServletException, IOException {
				response.setStatus(HttpServletResponse.SC_OK);
			}
		});
	}

	private SpringTestContext addFilter(Filter filter) {
		this.filters.add(filter);
		return this;
	}

	public ConfigurableApplicationContext getContext() {
		if (!this.context.isRunning()) {
			this.context.refresh();
		}
		return this.context;
	}

	public void autowire() {
		this.context.setServletContext(new MockServletContext());
		this.context.setServletConfig(new MockServletConfig());
		this.context.refresh();

		if (this.context.containsBean(SPRING_SECURITY_FILTER_CHAIN)) {
			MockMvc mockMvc = MockMvcBuilders.webAppContextSetup(this.context)
				.apply(springSecurity())
				.apply(new AddFilter()).build();
			this.context.getBeanFactory()
				.registerResolvableDependency(MockMvc.class, mockMvc);
		}

		AutowiredAnnotationBeanPostProcessor bpp = new AutowiredAnnotationBeanPostProcessor();
		bpp.setBeanFactory(this.context.getBeanFactory());
		bpp.processInjection(this.test);
	}

	private class AddFilter implements MockMvcConfigurer {
		public RequestPostProcessor beforeMockMvcCreated(
			ConfigurableMockMvcBuilder<?> builder, WebApplicationContext context) {
			builder.addFilters(SpringTestContext.this.filters.toArray(new Filter[0]));
			return null;
		}
	}
}
