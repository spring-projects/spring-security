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

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.web.PortMapperImpl;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.channel.ChannelDecisionManagerImpl;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.access.channel.InsecureChannelProcessor;
import org.springframework.security.web.access.channel.SecureChannelProcessor;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;

/**
 * Tests for {@link ChannelSecurityConfigurer}
 *
 * @author Rob Winch
 * @author Eleftheria Stein
 * @author Onur Kagan Ozcan
 */
@ExtendWith(SpringTestContextExtension.class)
public class ChannelSecurityConfigurerTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	MockMvc mvc;

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnInsecureChannelProcessor() {
		ObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(ObjectPostProcessorConfig.class).autowire();
		verify(ObjectPostProcessorConfig.objectPostProcessor).postProcess(any(InsecureChannelProcessor.class));
	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnSecureChannelProcessor() {
		ObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(ObjectPostProcessorConfig.class).autowire();
		verify(ObjectPostProcessorConfig.objectPostProcessor).postProcess(any(SecureChannelProcessor.class));
	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnChannelDecisionManagerImpl() {
		ObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(ObjectPostProcessorConfig.class).autowire();
		verify(ObjectPostProcessorConfig.objectPostProcessor).postProcess(any(ChannelDecisionManagerImpl.class));
	}

	@Test
	public void configureWhenRegisteringObjectPostProcessorThenInvokedOnChannelProcessingFilter() {
		ObjectPostProcessorConfig.objectPostProcessor = spy(ReflectingObjectPostProcessor.class);
		this.spring.register(ObjectPostProcessorConfig.class).autowire();
		verify(ObjectPostProcessorConfig.objectPostProcessor).postProcess(any(ChannelProcessingFilter.class));
	}

	@Test
	public void requiresChannelWhenInvokesTwiceThenUsesOriginalRequiresSecure() throws Exception {
		this.spring.register(DuplicateInvocationsDoesNotOverrideConfig.class).autowire();
		this.mvc.perform(get("/")).andExpect(redirectedUrl("https://localhost/"));
	}

	@Test
	public void requestWhenRequiresChannelConfiguredInLambdaThenRedirectsToHttps() throws Exception {
		this.spring.register(RequiresChannelInLambdaConfig.class).autowire();
		this.mvc.perform(get("/")).andExpect(redirectedUrl("https://localhost/"));
	}

	@Test
	public void requestWhenRequiresChannelConfiguredWithUrlRedirectThenRedirectsToUrlWithHttps() throws Exception {
		this.spring.register(RequiresChannelWithTestUrlRedirectStrategy.class).autowire();
		this.mvc.perform(get("/")).andExpect(redirectedUrl("https://localhost/test"));
	}

	// gh-10956
	@Test
	public void requestWhenRequiresChannelWithMultiMvcMatchersThenRedirectsToHttps() throws Exception {
		this.spring.register(RequiresChannelMultiMvcMatchersConfig.class).autowire();
		this.mvc.perform(get("/test-1")).andExpect(redirectedUrl("https://localhost/test-1"));
		this.mvc.perform(get("/test-2")).andExpect(redirectedUrl("https://localhost/test-2"));
		this.mvc.perform(get("/test-3")).andExpect(redirectedUrl("https://localhost/test-3"));
	}

	// gh-10956
	@Test
	public void requestWhenRequiresChannelWithMultiMvcMatchersInLambdaThenRedirectsToHttps() throws Exception {
		this.spring.register(RequiresChannelMultiMvcMatchersInLambdaConfig.class).autowire();
		this.mvc.perform(get("/test-1")).andExpect(redirectedUrl("https://localhost/test-1"));
		this.mvc.perform(get("/test-2")).andExpect(redirectedUrl("https://localhost/test-2"));
		this.mvc.perform(get("/test-3")).andExpect(redirectedUrl("https://localhost/test-3"));
	}

	@Configuration
	@EnableWebSecurity
	static class ObjectPostProcessorConfig {

		static ObjectPostProcessor<Object> objectPostProcessor;

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requiresChannel()
					.anyRequest().requiresSecure();
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
	static class DuplicateInvocationsDoesNotOverrideConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requiresChannel()
					.anyRequest().requiresSecure()
					.and()
				.requiresChannel();
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RequiresChannelInLambdaConfig {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requiresChannel((requiresChannel) ->
					requiresChannel
						.anyRequest().requiresSecure()
			);
			return http.build();
			// @formatter:on
		}

	}

	@Configuration
	@EnableWebSecurity
	static class RequiresChannelWithTestUrlRedirectStrategy {

		@Bean
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.portMapper()
					.portMapper(new PortMapperImpl())
					.and()
				.requiresChannel()
					.redirectStrategy(new TestUrlRedirectStrategy())
					.anyRequest()
					.requiresSecure();
			return http.build();
			// @formatter:on
		}

	}

	static class TestUrlRedirectStrategy implements RedirectStrategy {

		@Override
		public void sendRedirect(HttpServletRequest request, HttpServletResponse response, String url)
				throws IOException {
			String redirectUrl = url + "test";
			redirectUrl = response.encodeRedirectURL(redirectUrl);
			response.sendRedirect(redirectUrl);
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class RequiresChannelMultiMvcMatchersConfig {

		@Bean
		@Order(Ordered.HIGHEST_PRECEDENCE)
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.portMapper()
					.portMapper(new PortMapperImpl())
					.and()
				.requiresChannel()
					.requestMatchers("/test-1")
						.requiresSecure()
					.requestMatchers("/test-2")
						.requiresSecure()
					.requestMatchers("/test-3")
						.requiresSecure()
					.anyRequest()
						.requiresInsecure();
			// @formatter:on
			return http.build();
		}

	}

	@Configuration
	@EnableWebSecurity
	@EnableWebMvc
	static class RequiresChannelMultiMvcMatchersInLambdaConfig {

		@Bean
		@Order(Ordered.HIGHEST_PRECEDENCE)
		SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.portMapper((port) -> port
					.portMapper(new PortMapperImpl())
				)
				.requiresChannel((channel) -> channel
					.requestMatchers("/test-1")
						.requiresSecure()
					.requestMatchers("/test-2")
						.requiresSecure()
					.requestMatchers("/test-3")
						.requiresSecure()
					.anyRequest()
						.requiresInsecure()
				);
			// @formatter:on
			return http.build();
		}

	}

}
