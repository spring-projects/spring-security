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

package org.springframework.security.config.annotation.web.configurers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.test.web.servlet.RequestCacheResultMatcher;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.RequestCacheAwareFilter;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMultipartHttpServletRequestBuilder;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.security.config.Customizer.withDefaults;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;

/**
 * Tests for {@link RequestCacheConfigurer}
 *
 * @author Rob Winch
 * @author Josh Cummings
 */
@ExtendWith(SpringTestContextExtension.class)
public class RequestCacheConfigurerTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnExceptionTranslationFilter() {
		this.spring.register(ObjectPostProcessorConfig.class, DefaultSecurityConfig.class).autowire();
		verify(ObjectPostProcessorConfig.objectPostProcessor).postProcess(any(RequestCacheAwareFilter.class));
	}

	@Test
	public void getWhenInvokingExceptionHandlingTwiceThenOriginalEntryPointUsed() throws Exception {
		this.spring.register(InvokeTwiceDoesNotOverrideConfig.class).autowire();
		this.mvc.perform(get("/"));
		verify(InvokeTwiceDoesNotOverrideConfig.requestCache).getMatchingRequest(any(HttpServletRequest.class),
				any(HttpServletResponse.class));
	}

	@Test
	public void getWhenBookmarkedUrlIsFaviconIcoThenPostAuthenticationRedirectsToRoot() throws Exception {
		this.spring.register(RequestCacheDefaultsConfig.class, DefaultSecurityConfig.class).autowire();
		// @formatter:off
		MockHttpSession session = (MockHttpSession) this.mvc.perform(get("/favicon.ico"))
				.andExpect(redirectedUrl("http://localhost/login"))
				.andReturn()
				.getRequest()
				.getSession();
		// @formatter:on
		// ignores favicon.ico
		this.mvc.perform(formLogin(session)).andExpect(redirectedUrl("/"));
	}

	@Test
	public void getWhenBookmarkedUrlIsFaviconPngThenPostAuthenticationRedirectsToRoot() throws Exception {
		this.spring.register(RequestCacheDefaultsConfig.class, DefaultSecurityConfig.class).autowire();
		// @formatter:off
		MockHttpSession session = (MockHttpSession) this.mvc.perform(get("/favicon.png"))
				.andExpect(redirectedUrl("http://localhost/login"))
				.andReturn()
				.getRequest()
				.getSession();
		// @formatter:on
		// ignores favicon.png
		this.mvc.perform(formLogin(session)).andExpect(redirectedUrl("/"));
	}

	// SEC-2321
	@Test
	public void getWhenBookmarkedRequestIsApplicationJsonThenPostAuthenticationRedirectsToRoot() throws Exception {
		this.spring.register(RequestCacheDefaultsConfig.class, DefaultSecurityConfig.class).autowire();
		MockHttpServletRequestBuilder request = get("/messages").header(HttpHeaders.ACCEPT, MediaType.APPLICATION_JSON);
		// @formatter:off
		MockHttpSession session = (MockHttpSession) this.mvc.perform(request)
				.andExpect(redirectedUrl("http://localhost/login"))
				.andReturn()
				.getRequest()
				.getSession();
		// @formatter:on
		// ignores application/json
		// This is desirable since JSON requests are typically not invoked directly from
		// the browser and we don't want the browser to replay them
		this.mvc.perform(formLogin(session)).andExpect(redirectedUrl("/"));
	}

	// SEC-2321
	@Test
	public void getWhenBookmarkedRequestIsXRequestedWithThenPostAuthenticationRedirectsToRoot() throws Exception {
		this.spring.register(RequestCacheDefaultsConfig.class, DefaultSecurityConfig.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder xRequestedWith = get("/messages")
				.header("X-Requested-With", "XMLHttpRequest");
		MockHttpSession session = (MockHttpSession) this.mvc
				.perform(xRequestedWith)
				.andExpect(redirectedUrl("http://localhost/login"))
				.andReturn()
				.getRequest()
				.getSession();
		// @formatter:on
		this.mvc.perform(formLogin(session)).andExpect(redirectedUrl("/"));
		// This is desirable since XHR requests are typically not invoked directly from
		// the browser and we don't want the browser to replay them
	}

	@Test
	public void getWhenBookmarkedRequestIsTextEventStreamThenPostAuthenticationRedirectsToRoot() throws Exception {
		this.spring.register(RequestCacheDefaultsConfig.class, DefaultSecurityConfig.class).autowire();
		MockHttpServletRequestBuilder request = get("/messages").header(HttpHeaders.ACCEPT,
				MediaType.TEXT_EVENT_STREAM);
		// @formatter:off
		MockHttpSession session = (MockHttpSession) this.mvc.perform(request)
				.andExpect(redirectedUrl("http://localhost/login"))
				.andReturn()
				.getRequest()
				.getSession();
		// @formatter:on
		// ignores text/event-stream
		// This is desirable since event-stream requests are typically not invoked
		// directly from the browser and we don't want the browser to replay them
		this.mvc.perform(formLogin(session)).andExpect(redirectedUrl("/"));
	}

	@Test
	public void getWhenBookmarkedRequestIsAllMediaTypeThenPostAuthenticationRemembers() throws Exception {
		this.spring.register(RequestCacheDefaultsConfig.class, DefaultSecurityConfig.class).autowire();
		MockHttpServletRequestBuilder request = get("/messages").header(HttpHeaders.ACCEPT, MediaType.ALL);
		// @formatter:off
		MockHttpSession session = (MockHttpSession) this.mvc.perform(request)
				.andExpect(redirectedUrl("http://localhost/login"))
				.andReturn()
				.getRequest()
				.getSession();
		// @formatter:on
		this.mvc.perform(formLogin(session)).andExpect(RequestCacheResultMatcher.redirectToCachedRequest());
	}

	@Test
	public void getWhenBookmarkedRequestIsTextHtmlThenPostAuthenticationRemembers() throws Exception {
		this.spring.register(RequestCacheDefaultsConfig.class, DefaultSecurityConfig.class).autowire();
		MockHttpServletRequestBuilder request = get("/messages").header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML);
		// @formatter:off
		MockHttpSession session = (MockHttpSession) this.mvc.perform(request)
				.andExpect(redirectedUrl("http://localhost/login"))
				.andReturn()
				.getRequest()
				.getSession();
		// @formatter:on
		this.mvc.perform(formLogin(session)).andExpect(RequestCacheResultMatcher.redirectToCachedRequest());
	}

	@Test
	public void getWhenBookmarkedRequestIsChromeThenPostAuthenticationRemembers() throws Exception {
		this.spring.register(RequestCacheDefaultsConfig.class, DefaultSecurityConfig.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder request = get("/messages")
				.header(HttpHeaders.ACCEPT, "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8");
		MockHttpSession session = (MockHttpSession) this.mvc.perform(request)
				.andExpect(redirectedUrl("http://localhost/login"))
				.andReturn()
				.getRequest()
				.getSession();
		// @formatter:on
		this.mvc.perform(formLogin(session)).andExpect(RequestCacheResultMatcher.redirectToCachedRequest());
	}

	@Test
	public void getWhenBookmarkedRequestIsRequestedWithAndroidThenPostAuthenticationRemembers() throws Exception {
		this.spring.register(RequestCacheDefaultsConfig.class, DefaultSecurityConfig.class).autowire();
		// @formatter:off
		MockHttpServletRequestBuilder request = get("/messages")
				.header("X-Requested-With", "com.android");
		MockHttpSession session = (MockHttpSession) this.mvc.perform(request)
				.andExpect(redirectedUrl("http://localhost/login"))
				.andReturn()
				.getRequest()
				.getSession();
		// @formatter:on
		this.mvc.perform(formLogin(session)).andExpect(RequestCacheResultMatcher.redirectToCachedRequest());
	}

	// gh-6102
	@Test
	public void getWhenRequestCacheIsDisabledThenExceptionTranslationFilterDoesNotStoreRequest() throws Exception {
		this.spring.register(RequestCacheDisabledConfig.class, DefaultSecurityConfig.class).autowire();
		// @formatter:off
		MockHttpSession session = (MockHttpSession) this.mvc.perform(get("/bob"))
				.andReturn()
				.getRequest()
				.getSession();
		// @formatter:on
		this.mvc.perform(formLogin(session)).andExpect(redirectedUrl("/"));
	}

	// SEC-7060
	@Test
	public void postWhenRequestIsMultipartThenPostAuthenticationRedirectsToRoot() throws Exception {
		this.spring.register(RequestCacheDefaultsConfig.class, DefaultSecurityConfig.class).autowire();
		MockMultipartFile aFile = new MockMultipartFile("aFile", "A_FILE".getBytes());
		MockMultipartHttpServletRequestBuilder request = multipart("/upload").file(aFile);
		// @formatter:off
		MockHttpSession session = (MockHttpSession) this.mvc.perform(request)
				.andReturn()
				.getRequest()
				.getSession();
		// @formatter:on
		this.mvc.perform(formLogin(session)).andExpect(redirectedUrl("/"));
	}

	@Test
	public void getWhenRequestCacheIsDisabledInLambdaThenExceptionTranslationFilterDoesNotStoreRequest()
			throws Exception {
		this.spring.register(RequestCacheDisabledInLambdaConfig.class, DefaultSecurityConfig.class).autowire();
		// @formatter:off
		MockHttpSession session = (MockHttpSession) this.mvc.perform(get("/bob"))
				.andReturn()
				.getRequest()
				.getSession();
		// @formatter:on
		this.mvc.perform(formLogin(session)).andExpect(redirectedUrl("/"));
	}

	@Test
	public void getWhenRequestCacheInLambdaThenRedirectedToCachedPage() throws Exception {
		this.spring.register(RequestCacheInLambdaConfig.class, DefaultSecurityConfig.class).autowire();
		// @formatter:off
		MockHttpSession session = (MockHttpSession) this.mvc.perform(get("/bob"))
				.andReturn()
				.getRequest()
				.getSession();
		// @formatter:on
		this.mvc.perform(formLogin(session)).andExpect(RequestCacheResultMatcher.redirectToCachedRequest());
	}

	@Test
	public void getWhenCustomRequestCacheInLambdaThenCustomRequestCacheUsed() throws Exception {
		this.spring.register(CustomRequestCacheInLambdaConfig.class, DefaultSecurityConfig.class).autowire();
		// @formatter:off
		MockHttpSession session = (MockHttpSession) this.mvc.perform(get("/bob"))
				.andReturn()
				.getRequest()
				.getSession();
		// @formatter:on
		this.mvc.perform(formLogin(session)).andExpect(redirectedUrl("/"));
	}

	private static RequestBuilder formLogin(MockHttpSession session) {
		// @formatter:off
		return post("/login")
				.param("username", "user")
				.param("password", "password")
				.session(session)
				.with(csrf());
		// @formatter:on
	}

	@Configuration
	@EnableWebSecurity
	static class ObjectPostProcessorConfig {

		static ObjectPostProcessor<Object> objectPostProcessor = spy(ReflectingObjectPostProcessor.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requestCache();
			return http.build();
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

	@Configuration
	@EnableWebSecurity
	static class InvokeTwiceDoesNotOverrideConfig {

		static RequestCache requestCache = mock(RequestCache.class);

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requestCache()
					.requestCache(requestCache)
					.and()
				.requestCache();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RequestCacheDefaultsConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.formLogin();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RequestCacheDisabledConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeHttpRequests((requests) -> requests
						.anyRequest().authenticated()
				)
				.formLogin(Customizer.withDefaults())
				.requestCache((cache) -> cache.disable());
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RequestCacheDisabledInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authorizeRequests) ->
					authorizeRequests
						.anyRequest().authenticated()
				)
				.formLogin(withDefaults())
				.requestCache(RequestCacheConfigurer::disable);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RequestCacheInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authorizeRequests) ->
					authorizeRequests
						.anyRequest().authenticated()
				)
				.formLogin(withDefaults())
				.requestCache(withDefaults());
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class CustomRequestCacheInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.authorizeRequests((authorizeRequests) ->
					authorizeRequests
						.anyRequest().authenticated()
				)
				.formLogin(withDefaults())
				.requestCache((requestCache) ->
					requestCache
						.requestCache(new NullRequestCache())
				);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
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
			// @formatter:on
		}

	}

}
