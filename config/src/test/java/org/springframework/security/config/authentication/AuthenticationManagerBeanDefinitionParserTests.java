/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.authentication;

import static org.assertj.core.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.context.ApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.util.FieldUtils;

/**
 *
 * @author Luke Taylor
 */
public class AuthenticationManagerBeanDefinitionParserTests {
	private static final String CONTEXT = "<authentication-manager id='am'>"
			+ "    <authentication-provider>"
			+ "        <user-service>"
			+ "            <user name='bob' password='{noop}bobspassword' authorities='ROLE_A,ROLE_B' />"
			+ "        </user-service>" + "    </authentication-provider>"
			+ "</authentication-manager>";
	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Test
	// SEC-1225
	public void providersAreRegisteredAsTopLevelBeans() throws Exception {
		ConfigurableApplicationContext context = this.spring.context(CONTEXT)
			.getContext();
		assertThat(context.getBeansOfType(AuthenticationProvider.class)).hasSize(1);
	}

	@Test
	public void eventsArePublishedByDefault() throws Exception {
		ConfigurableApplicationContext appContext = this.spring.context(CONTEXT)
			.getContext();
		AuthListener listener = new AuthListener();
		appContext.addApplicationListener(listener);

		ProviderManager pm = (ProviderManager) appContext
				.getBeansOfType(ProviderManager.class).values().toArray()[0];
		Object eventPublisher = FieldUtils.getFieldValue(pm, "eventPublisher");
		assertThat(eventPublisher).isNotNull();
		assertThat(eventPublisher instanceof DefaultAuthenticationEventPublisher).isTrue();

		pm.authenticate(new UsernamePasswordAuthenticationToken("bob", "bobspassword"));
		assertThat(listener.events).hasSize(1);
	}

	@Test
	public void credentialsAreClearedByDefault() throws Exception {
		ConfigurableApplicationContext appContext = this.spring.context(CONTEXT)
			.getContext();
		ProviderManager pm = (ProviderManager) appContext
				.getBeansOfType(ProviderManager.class).values().toArray()[0];
		assertThat(pm.isEraseCredentialsAfterAuthentication()).isTrue();
	}

	@Test
	public void clearCredentialsPropertyIsRespected() throws Exception {
		ConfigurableApplicationContext appContext = this.spring.context("<authentication-manager erase-credentials='false'/>")
			.getContext();
		ProviderManager pm = (ProviderManager) appContext
				.getBeansOfType(ProviderManager.class).values().toArray()[0];
		assertThat(pm.isEraseCredentialsAfterAuthentication()).isFalse();
	}

	private static class AuthListener implements
			ApplicationListener<AbstractAuthenticationEvent> {
		List<AbstractAuthenticationEvent> events = new ArrayList<AbstractAuthenticationEvent>();

		public void onApplicationEvent(AbstractAuthenticationEvent event) {
			this.events.add(event);
		}
	}
}
