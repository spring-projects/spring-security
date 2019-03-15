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

import static org.assertj.core.api.Assertions.*;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;
import org.springframework.context.ApplicationListener;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.DefaultAuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
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
			+ "            <user name='bob' password='bobspassword' authorities='ROLE_A,ROLE_B' />"
			+ "        </user-service>" + "    </authentication-provider>"
			+ "</authentication-manager>";
	private AbstractXmlApplicationContext appContext;

	@Test
	// SEC-1225
	public void providersAreRegisteredAsTopLevelBeans() throws Exception {
		setContext(CONTEXT);
		assertThat(appContext.getBeansOfType(AuthenticationProvider.class)).hasSize(1);
	}

	@Test
	public void eventsArePublishedByDefault() throws Exception {
		setContext(CONTEXT);
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
		setContext(CONTEXT);
		ProviderManager pm = (ProviderManager) appContext
				.getBeansOfType(ProviderManager.class).values().toArray()[0];
		assertThat(pm.isEraseCredentialsAfterAuthentication()).isTrue();
	}

	@Test
	public void clearCredentialsPropertyIsRespected() throws Exception {
		setContext("<authentication-manager erase-credentials='false'/>");
		ProviderManager pm = (ProviderManager) appContext
				.getBeansOfType(ProviderManager.class).values().toArray()[0];
		assertThat(pm.isEraseCredentialsAfterAuthentication()).isFalse();
	}

	private void setContext(String context) {
		appContext = new InMemoryXmlApplicationContext(context);
	}

	private static class AuthListener implements
			ApplicationListener<AbstractAuthenticationEvent> {
		List<AbstractAuthenticationEvent> events = new ArrayList<AbstractAuthenticationEvent>();

		public void onApplicationEvent(AbstractAuthenticationEvent event) {
			events.add(event);
		}
	}
}
