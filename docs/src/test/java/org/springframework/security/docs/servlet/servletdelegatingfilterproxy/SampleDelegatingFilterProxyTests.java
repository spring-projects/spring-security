/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.docs.servlet.servletdelegatingfilterproxy;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.servlet.MockServletContext;
import org.springframework.util.Assert;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.StaticWebApplicationContext;

import java.io.IOException;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class SampleDelegatingFilterProxyTests {

	@Test
	void testFilter() throws ServletException, IOException {
		ServletContext sc = new MockServletContext();
		StaticWebApplicationContext wac = new StaticWebApplicationContext();
		wac.registerSingleton("targetFilter", MockFilter.class);
		wac.setServletContext(sc);
		wac.refresh();
		sc.setAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, wac);

		MockFilter targetFilter = (MockFilter) wac.getBean("targetFilter");
		MockFilterConfig proxyConfig = new MockFilterConfig(sc);
		proxyConfig.addInitParameter("targetBeanName", "targetFilter");
		SampleDelegatingFilterProxy filterProxy = new SampleDelegatingFilterProxy("targetFilter", wac);
		filterProxy.init(proxyConfig);

		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		filterProxy.doFilter(request, response, null);

		assertThat(targetFilter.filterConfig).isNull();
		assertThat(request.getAttribute("called")).isEqualTo(Boolean.TRUE);

		filterProxy.destroy();
		assertThat(targetFilter.filterConfig).isNull();
	}

	private static class MockFilter implements Filter {

		private FilterConfig filterConfig;

		@Override
		public void init(FilterConfig filterConfig) throws ServletException {
			this.filterConfig = filterConfig;
		}

		@Override
		public void doFilter(ServletRequest request, ServletResponse response,
				FilterChain chain) throws java.io.IOException, ServletException {
			request.setAttribute("called", Boolean.TRUE);
		}

		@Override
		public void destroy() {
			this.filterConfig = null;
		}
	}

	private static class MockFilterConfig  implements FilterConfig {
		private final ServletContext servletContext;

		private final String filterName;

		private final Map<String, String> initParameters = new LinkedHashMap<>();

		public MockFilterConfig(ServletContext servletContext) {
			this.servletContext = servletContext;
			this.filterName = "";
		}

		@Override
		public String getFilterName() {
			return this.filterName;
		}

		@Override
		public ServletContext getServletContext() {
			return this.servletContext;
		}

		public void addInitParameter(String name, String value) {
			Assert.notNull(name, "Parameter name must not be null");
			this.initParameters.put(name, value);
		}

		@Override
		public String getInitParameter(String name) {
			Assert.notNull(name, "Parameter name must not be null");
			return this.initParameters.get(name);
		}

		@Override
		public Enumeration<String> getInitParameterNames() {
			return Collections.enumeration(this.initParameters.keySet());
		}
	}
}
