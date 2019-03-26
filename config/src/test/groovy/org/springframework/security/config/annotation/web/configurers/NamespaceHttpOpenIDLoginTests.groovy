

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

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.BaseWebConfig;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.openid.OpenID4JavaConsumer
import org.springframework.security.openid.OpenIDAuthenticationFilter
import org.springframework.security.openid.OpenIDAuthenticationProvider
import org.springframework.security.openid.OpenIDAuthenticationToken;
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource

/**
 * Tests to verify that all the functionality of <openid-login> attributes is present
 *
 * @author Rob Winch
 *
 */
public class NamespaceHttpOpenIDLoginTests extends BaseSpringSpec {
	def "http/openid-login"() {
		when:
			loadConfig(OpenIDLoginConfig)
		then:
			findFilter(OpenIDAuthenticationFilter).consumer.class == OpenID4JavaConsumer
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.getRedirectedUrl() == "http://localhost/login"
		when: "fail to log in"
			super.setup()
			request.servletPath = "/login/openid"
			request.method = "POST"
			springSecurityFilterChain.doFilter(request,response,chain)
		then: "sent to login error page"
			response.getRedirectedUrl() == "/login?error"
	}

	@Configuration
	static class OpenIDLoginConfig extends BaseWebConfig {
		protected void configure(HttpSecurity http) {
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.openidLogin()
					.permitAll();
		}
	}

	def "http/openid-login/attribute-exchange"() {
		when:
			loadConfig(OpenIDLoginAttributeExchangeConfig)
			OpenID4JavaConsumer consumer = findFilter(OpenIDAuthenticationFilter).consumer
		then:
			consumer.class == OpenID4JavaConsumer

			def googleAttrs = consumer.attributesToFetchFactory.createAttributeList("https://www.google.com/1")
			googleAttrs[0].name == "email"
			googleAttrs[0].type == "https://axschema.org/contact/email"
			googleAttrs[0].required
			googleAttrs[1].name == "firstname"
			googleAttrs[1].type == "https://axschema.org/namePerson/first"
			googleAttrs[1].required
			googleAttrs[2].name == "lastname"
			googleAttrs[2].type == "https://axschema.org/namePerson/last"
			googleAttrs[2].required

			def yahooAttrs = consumer.attributesToFetchFactory.createAttributeList("https://rwinch.yahoo.com/rwinch/id")
			yahooAttrs[0].name == "email"
			yahooAttrs[0].type == "https://schema.openid.net/contact/email"
			yahooAttrs[0].required
			yahooAttrs[1].name == "fullname"
			yahooAttrs[1].type == "https://axschema.org/namePerson"
			yahooAttrs[1].required
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.getRedirectedUrl() == "http://localhost/login"
		when: "fail to log in"
			super.setup()
			request.servletPath = "/login/openid"
			request.method = "POST"
			springSecurityFilterChain.doFilter(request,response,chain)
		then: "sent to login error page"
			response.getRedirectedUrl() == "/login?error"
	}

	@Configuration
	static class OpenIDLoginAttributeExchangeConfig extends BaseWebConfig {
		protected void configure(HttpSecurity http) {
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.openidLogin()
					.attributeExchange("https://www.google.com/.*") // attribute-exchange@identifier-match
						.attribute("email") // openid-attribute@name
							.type("https://axschema.org/contact/email") // openid-attribute@type
							.required(true) // openid-attribute@required
							.count(1) // openid-attribute@count
							.and()
						.attribute("firstname")
							.type("https://axschema.org/namePerson/first")
							.required(true)
							.and()
						.attribute("lastname")
							.type("https://axschema.org/namePerson/last")
							.required(true)
							.and()
						.and()
					.attributeExchange(".*yahoo.com.*")
						.attribute("email")
							.type("https://schema.openid.net/contact/email")
							.required(true)
							.and()
						.attribute("fullname")
							.type("https://axschema.org/namePerson")
							.required(true)
							.and()
						.and()
					.permitAll();
		}
	}

	def "http/openid-login custom"() {
		setup:
			loadConfig(OpenIDLoginCustomConfig)
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.getRedirectedUrl() == "http://localhost/authentication/login"
		when: "fail to log in"
			super.setup()
			request.servletPath = "/authentication/login/process"
			request.method = "POST"
			springSecurityFilterChain.doFilter(request,response,chain)
		then: "sent to login error page"
			response.getRedirectedUrl() == "/authentication/login?failed"
	}

	@Configuration
	static class OpenIDLoginCustomConfig extends BaseWebConfig {
		protected void configure(HttpSecurity http) throws Exception {
			boolean alwaysUseDefaultSuccess = true;
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.openidLogin()
					.permitAll()
					.loginPage("/authentication/login") // openid-login@login-page
					.failureUrl("/authentication/login?failed") // openid-login@authentication-failure-url
					.loginProcessingUrl("/authentication/login/process") // openid-login@login-processing-url
					.defaultSuccessUrl("/default", alwaysUseDefaultSuccess) // openid-login@default-target-url / openid-login@always-use-default-target
		}
	}

	def "http/openid-login custom refs"() {
		when:
			OpenIDLoginCustomRefsConfig.AUDS = Mock(AuthenticationUserDetailsService)
			loadConfig(OpenIDLoginCustomRefsConfig)
		then: "CustomWebAuthenticationDetailsSource is used"
			findFilter(OpenIDAuthenticationFilter).authenticationDetailsSource.class == CustomWebAuthenticationDetailsSource
			findAuthenticationProvider(OpenIDAuthenticationProvider).userDetailsService == OpenIDLoginCustomRefsConfig.AUDS
		when: "fail to log in"
			request.servletPath = "/login/openid"
			request.method = "POST"
			springSecurityFilterChain.doFilter(request,response,chain)
		then: "sent to login error page"
			response.getRedirectedUrl() == "/custom/failure"
	}

	@Configuration
	static class OpenIDLoginCustomRefsConfig extends BaseWebConfig {
		static AuthenticationUserDetailsService AUDS

		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.openidLogin()
					// if using UserDetailsService wrap with new UserDetailsByNameServiceWrapper<OpenIDAuthenticationToken>()
					.authenticationUserDetailsService(AUDS) // openid-login@user-service-ref
					.failureHandler(new SimpleUrlAuthenticationFailureHandler("/custom/failure")) // openid-login@authentication-failure-handler-ref
					.successHandler(new SavedRequestAwareAuthenticationSuccessHandler( defaultTargetUrl : "/custom/targetUrl" )) // openid-login@authentication-success-handler-ref
					.authenticationDetailsSource(new CustomWebAuthenticationDetailsSource()); // openid-login@authentication-details-source-ref
		}

		// only necessary to have easy access to the AuthenticationManager for testing/verification
		@Bean
		@Override
		public AuthenticationManager authenticationManagerBean()
				throws Exception {
			return super.authenticationManagerBean();
		}

	}

	static class CustomWebAuthenticationDetailsSource extends WebAuthenticationDetailsSource {}
}
