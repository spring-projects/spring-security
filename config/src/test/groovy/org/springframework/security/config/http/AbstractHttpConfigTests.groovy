/*
 * Copyright 2002-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.config.http

import javax.servlet.Filter
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.config.AbstractXmlConfigTests
import org.springframework.security.config.BeanIds
import org.springframework.security.web.FilterInvocation

import javax.servlet.http.HttpServletRequest

/**
 *
 * @author Rob Winch
 *
 */
abstract class AbstractHttpConfigTests extends AbstractXmlConfigTests {
	final int AUTO_CONFIG_FILTERS = 15;

	def httpAutoConfig(Closure c) {
		xml.http(['auto-config': 'true', 'use-expressions':false], c)
	}

	def httpAutoConfig(String matcher, Closure c) {
		xml.http(['auto-config': 'true', 'use-expressions':false, 'request-matcher': matcher], c)
	}

	def interceptUrl(String path, String authz) {
		xml.'intercept-url'(pattern: path, access: authz)
	}

	def interceptUrl(String path, String httpMethod, String authz) {
		xml.'intercept-url'(pattern: path, method: httpMethod, access: authz)
	}

	Filter getFilter(Class type) {
		List filters = getFilters("/any");

		for (f in filters) {
			if (f.class.isAssignableFrom(type)) {
				return f;
			}
		}

		return null;
	}

	List getFilters(String url) {
		springSecurityFilterChain.getFilters(url)
	}

	Filter getSpringSecurityFilterChain() {
		appContext.getBean(BeanIds.FILTER_CHAIN_PROXY)
	}

	FilterInvocation createFilterinvocation(String path, String method) {
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setMethod(method);
		request.setRequestURI(null);
		request.setServletPath(path);

		return new FilterInvocation(request, new MockHttpServletResponse(), new MockFilterChain());
	}

	def basicLogin(HttpServletRequest request, String username="user",String password="password") {
		def credentials = username + ":" + password
		request.addHeader("Authorization", "Basic " + credentials.bytes.encodeBase64())
	}
}
