/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.config.annotation.web.configurers

import org.springframework.context.annotation.Bean;

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

import org.springframework.context.annotation.Configuration
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.config.annotation.web.configuration.BaseWebConfig
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.firewall.DefaultHttpFirewall
import org.springframework.security.web.firewall.FirewalledRequest
import org.springframework.security.web.firewall.RequestRejectedException

/**
 * Tests to verify that all the functionality of <http-firewall> attributes is present
 *
 * @author Rob Winch
 *
 */
public class NamespaceHttpFirewallTests extends BaseSpringSpec {
	FilterChainProxy springSecurityFilterChain
	MockHttpServletRequest request
	MockHttpServletResponse response
	MockFilterChain chain

	def setup() {
		request = new MockHttpServletRequest("GET", "")
		response = new MockHttpServletResponse()
		chain = new MockFilterChain()
	}

	def "http-firewall"() {
		setup:
			loadConfig(HttpFirewallConfig)
			springSecurityFilterChain = context.getBean(FilterChainProxy)
			request.setPathInfo("/public/../private/")
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then: "the default firewall is used"
			thrown(RequestRejectedException)
	}

	@Configuration
	static class HttpFirewallConfig extends BaseWebConfig {
		protected void configure(HttpSecurity http) {
		}
	}

	def "http-firewall@ref"() {
		setup:
			loadConfig(CustomHttpFirewallConfig)
			springSecurityFilterChain = context.getBean(FilterChainProxy)
			request.setParameter("deny", "true")
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then: "the custom firewall is used"
			thrown(RequestRejectedException)
	}

	@Configuration
	static class CustomHttpFirewallConfig extends BaseWebConfig {
		@Override
		protected void configure(HttpSecurity http) { }

		@Override
		public void configure(WebSecurity builder)	throws Exception {
			builder
				.httpFirewall(new CustomHttpFirewall())
		}
	}

	def "http-firewall bean"() {
		setup:
		loadConfig(CustomHttpFirewallBeanConfig)
		springSecurityFilterChain = context.getBean(FilterChainProxy)
		request.setParameter("deny", "true")
		when:
		springSecurityFilterChain.doFilter(request,response,chain)
		then: "the custom firewall is used"
		thrown(RequestRejectedException)
	}

	@Configuration
	static class CustomHttpFirewallBeanConfig extends BaseWebConfig {
		@Override
		protected void configure(HttpSecurity http) { }

		@Bean
		CustomHttpFirewall firewall() {
			return new CustomHttpFirewall();
		}
	}

	static class CustomHttpFirewall extends DefaultHttpFirewall {

		@Override
		public FirewalledRequest getFirewalledRequest(HttpServletRequest request)
				throws RequestRejectedException {
			if(request.getParameter("deny")) {
				throw new RequestRejectedException("custom rejection")
			}
			return super.getFirewalledRequest(request)
		}

		@Override
		public HttpServletResponse getFirewalledResponse(
				HttpServletResponse response) {
			return super.getFirewalledRequest(response)
		}

	}
}
