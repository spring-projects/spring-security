/*
 * Copyright 2002-2022 the original author or authors.
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

import java.io.Closeable;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.AutowiredAnnotationBeanPostProcessor;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.util.InMemoryXmlWebApplicationContext;
import org.springframework.security.web.servlet.MockServletContext;
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

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class SpringTestContext implements Closeable {

	private Object test;

	private ConfigurableWebApplicationContext context;

	private List<Filter> filters = new ArrayList<>();

	private DeferAddFilter deferAddFilter = new DeferAddFilter();

	private List<Consumer<ConfigurableWebApplicationContext>> postProcessors = new ArrayList<>();

	public SpringTestContext(Object test) {
		setTest(test);
	}

	public void setTest(Object test) {
		this.test = test;
	}

	@Override
	public void close() {
		try {
			this.context.close();
		}
		catch (Exception ex) {
		}
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
		String[] locations = loader.processLocations(this.test.getClass(), configLocations);
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

	public SpringTestContext postProcessor(Consumer<ConfigurableWebApplicationContext> contextConsumer) {
		this.postProcessors.add(contextConsumer);
		return this;
	}

	public SpringTestContext mockMvcAfterSpringSecurityOk() {
		this.deferAddFilter.addFilter(new OncePerRequestFilter() {
			@Override
			protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
					FilterChain filterChain) {
				response.setStatus(HttpServletResponse.SC_OK);
			}
		});
		return this;
	}

	public SpringTestContext addFilter(Filter filter) {
		this.filters.add(filter);
		return this;
	}

	public ConfigurableWebApplicationContext getContext() {
		if (!this.context.isRunning()) {
			this.context.setServletContext(MockServletContext.mvc());
			this.context.setServletConfig(new MockServletConfig());
			this.context.refresh();
		}
		return this.context;
	}

	public void autowire() {
		this.context.setServletContext(MockServletContext.mvc());
		this.context.setServletConfig(new MockServletConfig());
		for (Consumer<ConfigurableWebApplicationContext> postProcessor : this.postProcessors) {
			postProcessor.accept(this.context);
		}
		this.context.refresh();
		if (this.context.containsBean(BeanIds.SPRING_SECURITY_FILTER_CHAIN)) {
			// @formatter:off
			MockMvc mockMvc = MockMvcBuilders.webAppContextSetup(this.context)
					.addFilters(this.filters.toArray(new Filter[0]))
					.apply(springSecurity())
					.apply(this.deferAddFilter)
					.build();
			// @formatter:on
			this.context.getBeanFactory().registerResolvableDependency(MockMvc.class, mockMvc);
		}
		AutowiredAnnotationBeanPostProcessor bpp = new AutowiredAnnotationBeanPostProcessor();
		bpp.setBeanFactory(this.context.getBeanFactory());
		bpp.processInjection(this.test);
	}

	private static class DeferAddFilter implements MockMvcConfigurer {

		private List<Filter> filters = new ArrayList<>();

		void addFilter(Filter filter) {
			this.filters.add(filter);
		}

		@Override
		public RequestPostProcessor beforeMockMvcCreated(ConfigurableMockMvcBuilder<?> builder,
				WebApplicationContext context) {
			builder.addFilters(this.filters.toArray(new Filter[0]));
			return null;
		}

	}

}
