/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.config.authentication;

import java.util.ArrayList;
import java.util.List;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.util.FieldUtils;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * @author Luke Taylor
 */
public class AuthenticationManagerBeanDefinitionParserTests {

	// @formatter:off
	private static final String CONTEXT = "<authentication-manager id='am'>"
			+ "    <authentication-provider>"
			+ "        <user-service>"
			+ "            <user name='bob' password='{noop}bobspassword' authorities='ROLE_A,ROLE_B' />"
			+ "        </user-service>"
			+ "    </authentication-provider>"
			+ "</authentication-manager>";
	// @formatter:on

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Test
	// SEC-1225
	public void providersAreRegisteredAsTopLevelBeans() {
		ConfigurableApplicationContext context = this.spring.context(CONTEXT).getContext();
		assertThat(context.getBeansOfType(AuthenticationProvider.class)).hasSize(1);
	}

	@Test
	public void eventsArePublishedByDefault() throws Exception {
		ConfigurableApplicationContext appContext = this.spring.context(CONTEXT).getContext();
		AuthListener listener = new AuthListener();
		appContext.addApplicationListener(listener);
		ProviderManager pm = (ProviderManager) appContext.getBeansOfType(ProviderManager.class).values().toArray()[0];
		Object eventPublisher = FieldUtils.getFieldValue(pm, "eventPublisher");
		assertThat(eventPublisher).isNotNull();
		assertThat(eventPublisher instanceof DefaultAuthenticationEventPublisher).isTrue();
		pm.authenticate(new UsernamePasswordAuthenticationToken("bob", "bobspassword"));
		assertThat(listener.events).hasSize(1);
	}

	@Test
	public void credentialsAreClearedByDefault() {
		ConfigurableApplicationContext appContext = this.spring.context(CONTEXT).getContext();
		ProviderManager pm = (ProviderManager) appContext.getBeansOfType(ProviderManager.class).values().toArray()[0];
		assertThat(pm.isEraseCredentialsAfterAuthentication()).isTrue();
	}

	@Test
	public void clearCredentialsPropertyIsRespected() {
		ConfigurableApplicationContext appContext = this.spring
				.context("<authentication-manager erase-credentials='false'/>").getContext();
		ProviderManager pm = (ProviderManager) appContext.getBeansOfType(ProviderManager.class).values().toArray()[0];
		assertThat(pm.isEraseCredentialsAfterAuthentication()).isFalse();
	}

	@Autowired
	MockMvc mockMvc;

	@Test
	public void passwordEncoderBeanUsed() throws Exception {
		// @formatter:off
		this.spring.context("<b:bean id='passwordEncoder' class='org.springframework.security.crypto.password.NoOpPasswordEncoder' factory-method='getInstance'/>"
				+ "<user-service>"
				+ "  <user name='user' password='password' authorities='ROLE_A,ROLE_B' />"
				+ "</user-service>"
				+ "<http/>")
				.mockMvcAfterSpringSecurityOk()
				.autowire();
		this.mockMvc.perform(get("/").with(httpBasic("user", "password")))
				.andExpect(status().isOk());
		// @formatter:on
	}

	private static class AuthListener implements ApplicationListener<AbstractAuthenticationEvent> {

		List<AbstractAuthenticationEvent> events = new ArrayList<>();

		@Override
		public void onApplicationEvent(AbstractAuthenticationEvent event) {
			this.events.add(event);
		}

	}

}
