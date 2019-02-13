/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.config.annotation.authentication.configurers;

import javax.servlet.Filter;
import javax.servlet.ServletException;
import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.web.context.ConfigurableWebApplicationContext;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link HeadersConfigurer}.
 *
 * @author Ankur Pathak
 */
public class HeadersConfigurerJavaTests {

	private boolean allowCircularReferences = false;
	private MockServletContext servletContext;
	private MockHttpServletRequest request;
	private MockHttpServletResponse response;
	private MockFilterChain chain;
	private ConfigurableWebApplicationContext context;


	@Before
	public void setUp() {
		this.servletContext = new MockServletContext();
		this.request = new MockHttpServletRequest(this.servletContext, "GET", "");
		this.response = new MockHttpServletResponse();
		this.chain = new MockFilterChain();
	}


	@After
	public void cleanup(){
		if (this.context != null){
			this.context.close();
		}
	}


	@EnableWebSecurity
	public static class HeadersAtTheBeginningOfRequestConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.headers()
					.addObjectPostProcessor(new ObjectPostProcessor<HeaderWriterFilter>() {
						@Override
						public HeaderWriterFilter postProcess(HeaderWriterFilter filter) {
							filter.setShouldWriteHeadersEagerly(true);
							return filter;
						}
					});
		}
	}

	@Test
	public void headersWrittenAtBeginningOfRequest() throws IOException, ServletException {
		this.context = loadConfig(HeadersAtTheBeginningOfRequestConfig.class);
		this.request.setSecure(true);
		getSpringSecurityFilterChain().doFilter(this.request, this.response, this.chain);
		assertThat(getResponseHeaders()).containsAllEntriesOf(new LinkedHashMap<String, String>(){{
			put("X-Content-Type-Options", "nosniff");
			put("X-Frame-Options", "DENY");
			put("Strict-Transport-Security", "max-age=31536000 ; includeSubDomains");
			put("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
			put("Expires", "0");
			put("Pragma", "no-cache");
			put("X-XSS-Protection", "1; mode=block");
		}});
	}


	@SuppressWarnings("unchecked")
	private Map<String, String > getResponseHeaders() {
		Map<String, String> headers = new LinkedHashMap<>();
		this.response.getHeaderNames().forEach(name -> {
			List values = this.response.getHeaderValues(name);
			headers.put(name, String.join(",", values));
		});
		return headers;
	}

	private ConfigurableWebApplicationContext loadConfig(Class<?>... configs) {
		AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
		context.register(configs);
		context.setAllowCircularReferences(this.allowCircularReferences);
		context.setServletContext(this.servletContext);
		context.refresh();
		return context;
	}

	private Filter getSpringSecurityFilterChain() {
		return this.context.getBean("springSecurityFilterChain", Filter.class);
	}
}
