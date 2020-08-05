/*
 * Copyright 2002-2019 the original author or authors.
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

import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.web.access.channel.ChannelDecisionManagerImpl;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.access.channel.InsecureChannelProcessor;
import org.springframework.security.web.access.channel.SecureChannelProcessor;
import org.springframework.test.web.servlet.MockMvc;

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
 */
public class ChannelSecurityConfigurerTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

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

	@EnableWebSecurity
	static class ObjectPostProcessorConfig extends WebSecurityConfigurerAdapter {

		static ObjectPostProcessor<Object> objectPostProcessor;

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requiresChannel()
					.anyRequest().requiresSecure();
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

	@Test
	public void requiresChannelWhenInvokesTwiceThenUsesOriginalRequiresSecure() throws Exception {
		this.spring.register(DuplicateInvocationsDoesNotOverrideConfig.class).autowire();

		mvc.perform(get("/")).andExpect(redirectedUrl("https://localhost/"));
	}

	@EnableWebSecurity
	static class DuplicateInvocationsDoesNotOverrideConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requiresChannel()
					.anyRequest().requiresSecure()
					.and()
				.requiresChannel();
			// @formatter:on
		}

	}

	@Test
	public void requestWhenRequiresChannelConfiguredInLambdaThenRedirectsToHttps() throws Exception {
		this.spring.register(RequiresChannelInLambdaConfig.class).autowire();

		mvc.perform(get("/")).andExpect(redirectedUrl("https://localhost/"));
	}

	@EnableWebSecurity
	static class RequiresChannelInLambdaConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// @formatter:off
			http
				.requiresChannel(requiresChannel ->
					requiresChannel
						.anyRequest().requiresSecure()
			);
			// @formatter:on
		}

	}

}
