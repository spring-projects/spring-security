/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.config.annotation.web.configuration;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.test.context.annotation.SecurityTestExecutionListeners;
import org.springframework.security.web.access.AuthorizationManagerWebInvocationPrivilegeEvaluator.HttpServletRequestTransformer;
import org.springframework.security.web.access.HandlerMappingIntrospectorRequestTransformer;
import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Checks that HandlerMappingIntrospectorRequestTransformer is autowired into
 * {@link org.springframework.security.web.access.AuthorizationManagerWebInvocationPrivilegeEvaluator}.
 *
 * @author Rob Winch
 */
@ContextConfiguration
@WebAppConfiguration
@ExtendWith({ SpringExtension.class })
@SecurityTestExecutionListeners
public class AuthorizationManagerWebInvocationPrivilegeEvaluatorConfigTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired(required = false)
	HttpServletRequestTransformer requestTransformer;

	@Autowired
	WebInvocationPrivilegeEvaluator wipe;

	@Test
	void mvcEnabledConfigThenHandlerMappingIntrospectorRequestTransformerBeanExists() {
		this.spring.register(MvcEnabledConfig.class).autowire();
		assertThat(this.requestTransformer).isInstanceOf(HandlerMappingIntrospectorRequestTransformer.class);
	}

	@Test
	void mvcNotEnabledThenNoRequestTransformerBeanExists() {
		this.spring.register(MvcNotEnabledConfig.class).autowire();
		assertThat(this.requestTransformer).isNull();
	}

	@Test
	void mvcNotEnabledAndTransformerThenWIPEDelegatesToTransformer() {
		this.spring.register(MvcNotEnabledConfig.class, TransformerConfig.class).autowire();

		this.wipe.isAllowed("/uri", TestAuthentication.authenticatedUser());

		verify(this.requestTransformer).transform(any());
	}

	@Configuration
	static class TransformerConfig {

		@Bean
		HttpServletRequestTransformer httpServletRequestTransformer() {
			return mock(HttpServletRequestTransformer.class);
		}

	}

	@Configuration
	@EnableWebMvc
	@EnableWebSecurity
	static class MvcEnabledConfig {

	}

	@Configuration
	@EnableWebSecurity
	static class MvcNotEnabledConfig {

	}

}
