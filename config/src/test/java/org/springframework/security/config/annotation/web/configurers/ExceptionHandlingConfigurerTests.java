/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.context.request.NativeWebRequest;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for {@link ExceptionHandlingConfigurer}
 *
 * @author Rob Winch
 * @author Josh Cummings
 */
public class ExceptionHandlingConfigurerTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	MockMvc mvc;

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnExceptionTranslationFilter() {
		this.spring.register(ObjectPostProcessorConfig.class, DefaultSecurityConfig.class).autowire();
		verify(ObjectPostProcessorConfig.objectPostProcessor).postProcess(any(ExceptionTranslationFilter.class));
	}

	// SEC-2199
	@Test
	public void getWhenAcceptHeaderIsApplicationXhtmlXmlThenRespondsWith302() throws Exception {
		this.spring.register(HttpBasicAndFormLoginEntryPointsConfig.class).autowire();
		this.mvc.perform(get("/").header(HttpHeaders.ACCEPT, MediaType.APPLICATION_XHTML_XML))
				.andExpect(status().isFound());
	}

	// SEC-2199
	@Test
	public void getWhenAcceptHeaderIsImageGifThenRespondsWith302() throws Exception {
		this.spring.register(HttpBasicAndFormLoginEntryPointsConfig.class).autowire();
		this.mvc.perform(get("/").header(HttpHeaders.ACCEPT, MediaType.IMAGE_GIF)).andExpect(status().isFound());
	}

	// SEC-2199
	@Test
	public void getWhenAcceptHeaderIsImageJpgThenRespondsWith302() throws Exception {
		this.spring.register(HttpBasicAndFormLoginEntryPointsConfig.class).autowire();
		this.mvc.perform(get("/").header(HttpHeaders.ACCEPT, MediaType.IMAGE_JPEG)).andExpect(status().isFound());
	}

	// SEC-2199
	@Test
	public void getWhenAcceptHeaderIsImagePngThenRespondsWith302() throws Exception {
		this.spring.register(HttpBasicAndFormLoginEntryPointsConfig.class).autowire();
		this.mvc.perform(get("/").header(HttpHeaders.ACCEPT, MediaType.IMAGE_PNG)).andExpect(status().isFound());
	}

	// SEC-2199
	@Test
	public void getWhenAcceptHeaderIsTextHtmlThenRespondsWith302() throws Exception {
		this.spring.register(HttpBasicAndFormLoginEntryPointsConfig.class).autowire();
		this.mvc.perform(get("/").header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML)).andExpect(status().isFound());
	}

	// SEC-2199
	@Test
	public void getWhenAcceptHeaderIsTextPlainThenRespondsWith302() throws Exception {
		this.spring.register(HttpBasicAndFormLoginEntryPointsConfig.class).autowire();
		this.mvc.perform(get("/").header(HttpHeaders.ACCEPT, MediaType.TEXT_PLAIN)).andExpect(status().isFound());
	}

	// SEC-2199
	@Test
	public void getWhenAcceptHeaderIsApplicationAtomXmlThenRespondsWith401() throws Exception {
		this.spring.register(HttpBasicAndFormLoginEntryPointsConfig.class).autowire();
		this.mvc.perform(get("/").header(HttpHeaders.ACCEPT, MediaType.APPLICATION_ATOM_XML))
				.andExpect(status().isUnauthorized());
	}

	// SEC-2199
	@Test
	public void getWhenAcceptHeaderIsApplicationFormUrlEncodedThenRespondsWith401() throws Exception {
		this.spring.register(HttpBasicAndFormLoginEntryPointsConfig.class).autowire();
		this.mvc.perform(get("/").header(HttpHeaders.ACCEPT, MediaType.APPLICATION_FORM_URLENCODED))
				.andExpect(status().isUnauthorized());
	}

	// SEC-2199
	@Test
	public void getWhenAcceptHeaderIsApplicationJsonThenRespondsWith401() throws Exception {
		this.spring.register(HttpBasicAndFormLoginEntryPointsConfig.class).autowire();
		this.mvc.perform(get("/").header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON))
				.andExpect(status().isUnauthorized());
	}

	// SEC-2199
	@Test
	public void getWhenAcceptHeaderIsApplicationOctetStreamThenRespondsWith401() throws Exception {
		this.spring.register(HttpBasicAndFormLoginEntryPointsConfig.class).autowire();
		this.mvc.perform(get("/").header(HttpHeaders.ACCEPT, MediaType.APPLICATION_OCTET_STREAM))
				.andExpect(status().isUnauthorized());
	}

	// SEC-2199
	@Test
	public void getWhenAcceptHeaderIsMultipartFormDataThenRespondsWith401() throws Exception {
		this.spring.register(HttpBasicAndFormLoginEntryPointsConfig.class).autowire();
		this.mvc.perform(get("/").header(HttpHeaders.ACCEPT, MediaType.MULTIPART_FORM_DATA))
				.andExpect(status().isUnauthorized());
	}

	// SEC-2199
	@Test
	public void getWhenAcceptHeaderIsTextXmlThenRespondsWith401() throws Exception {
		this.spring.register(HttpBasicAndFormLoginEntryPointsConfig.class).autowire();
		this.mvc.perform(get("/").header(HttpHeaders.ACCEPT, MediaType.TEXT_XML)).andExpect(status().isUnauthorized());
	}

	// gh-4831
	@Test
	public void getWhenAcceptIsAnyThenRespondsWith401() throws Exception {
		this.spring.register(DefaultSecurityConfig.class).autowire();
		this.mvc.perform(get("/").header(HttpHeaders.ACCEPT, MediaType.ALL)).andExpect(status().isUnauthorized());
	}

	@Test
	public void getWhenAcceptIsChromeThenRespondsWith302() throws Exception {
		this.spring.register(DefaultSecurityConfig.class).autowire();
		this.mvc.perform(get("/").header(HttpHeaders.ACCEPT,
				"text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"))
				.andExpect(status().isFound());
	}

	@Test
	public void getWhenAcceptIsTextPlainAndXRequestedWithIsXHRThenRespondsWith401() throws Exception {
		this.spring.register(HttpBasicAndFormLoginEntryPointsConfig.class).autowire();
		this.mvc.perform(get("/").header("Accept", MediaType.TEXT_PLAIN).header("X-Requested-With", "XMLHttpRequest"))
				.andExpect(status().isUnauthorized());
	}

	@Test
	public void getWhenCustomContentNegotiationStrategyThenStrategyIsUsed() throws Exception {
		this.spring.register(OverrideContentNegotiationStrategySharedObjectConfig.class, DefaultSecurityConfig.class)
				.autowire();
		this.mvc.perform(get("/"));
		verify(OverrideContentNegotiationStrategySharedObjectConfig.CNS, atLeastOnce())
				.resolveMediaTypes(any(NativeWebRequest.class));
	}

	@Test
	public void getWhenUsingDefaultsAndUnauthenticatedThenRedirectsToLogin() throws Exception {
		this.spring.register(DefaultHttpConfig.class).autowire();
		this.mvc.perform(get("/").header(HttpHeaders.ACCEPT, "bogus/type"))
				.andExpect(redirectedUrl("http://localhost/login"));
	}

	@Test
	public void getWhenDeclaringHttpBasicBeforeFormLoginThenRespondsWith401() throws Exception {
		this.spring.register(BasicAuthenticationEntryPointBeforeFormLoginConfig.class).autowire();
		this.mvc.perform(get("/").header(HttpHeaders.ACCEPT, "bogus/type")).andExpect(status().isUnauthorized());
	}

	@Test
	public void getWhenInvokingExceptionHandlingTwiceThenOriginalEntryPointUsed() throws Exception {
		this.spring.register(InvokeTwiceDoesNotOverrideConfig.class).autowire();
		this.mvc.perform(get("/"));
		verify(InvokeTwiceDoesNotOverrideConfig.AEP).commence(any(HttpServletRequest.class),
				any(HttpServletResponse.class), any(AuthenticationException.class));
	}

	@EnableWebSecurity
	static class ObjectPostProcessorConfig extends WebSecurityConfigurerAdapter {

		static ObjectPostProcessor<Object> objectPostProcessor = spy(ReflectingObjectPostProcessor.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.exceptionHandling();
			// @formatter:on
		}

		@Bean
		static ObjectPostProcessor<Object> objectPostProcessor() {
			return objectPostProcessor;
		}

	}

	static class ReflectingObjectPostProcessor implements ObjectPostProcessor<Object> {

		@Override
		public <O> O postProcess(O object) {
			return object;
		}

	}

	@EnableWebSecurity
	static class DefaultSecurityConfig {

		@Bean
		InMemoryUserDetailsManager userDetailsManager() {
			// @formatter:off
			return new InMemoryUserDetailsManager(User.withDefaultPasswordEncoder()
				.username("user")
				.password("password")
				.roles("USER")
				.build()
			);
			// @formatter:off
		}
	}
	@EnableWebSecurity
	static class HttpBasicAndFormLoginEntryPointsConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
				.inMemoryAuthentication()
					.withUser("user").password("password").roles("USER");
		}
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.httpBasic()
					.and()
				.formLogin();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class OverrideContentNegotiationStrategySharedObjectConfig extends WebSecurityConfigurerAdapter {

		static ContentNegotiationStrategy CNS = mock(ContentNegotiationStrategy.class);

		@Bean
		static ContentNegotiationStrategy cns() {
			return CNS;
		}

	}

	@EnableWebSecurity
	static class DefaultHttpConfig extends WebSecurityConfigurerAdapter {

	}

	@EnableWebSecurity
	static class BasicAuthenticationEntryPointBeforeFormLoginConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.httpBasic()
					.and()
				.formLogin();
			// @formatter:on
		}

	}

	@EnableWebSecurity
	static class InvokeTwiceDoesNotOverrideConfig extends WebSecurityConfigurerAdapter {

		static AuthenticationEntryPoint AEP = mock(AuthenticationEntryPoint.class);

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:on
			http.authorizeRequests().anyRequest().authenticated().and().exceptionHandling()
					.authenticationEntryPoint(AEP).and().exceptionHandling();
			// @formatter:off
		}
	}
}
