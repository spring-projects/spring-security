/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.config.http;

import java.util.Collection;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.test.SpringTestContext;
import org.springframework.security.config.test.SpringTestContextExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.Transient;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

/**
 * @author Josh Cummings
 */
@ExtendWith(SpringTestContextExtension.class)
public class SessionManagementConfigTransientAuthenticationTests {

	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/http/SessionManagementConfigTransientAuthenticationTests";

	@Autowired
	MockMvc mvc;

	public final SpringTestContext spring = new SpringTestContext(this);

	@Test
	public void postWhenTransientAuthenticationThenNoSessionCreated() throws Exception {
		this.spring.configLocations(this.xml("WithTransientAuthentication")).autowire();
		MvcResult result = this.mvc.perform(post("/login")).andReturn();
		assertThat(result.getRequest().getSession(false)).isNull();
	}

	@Test
	public void postWhenTransientAuthenticationThenAlwaysSessionOverrides() throws Exception {
		this.spring.configLocations(this.xml("CreateSessionAlwaysWithTransientAuthentication")).autowire();
		MvcResult result = this.mvc.perform(post("/login")).andReturn();
		assertThat(result.getRequest().getSession(false)).isNotNull();
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

	static class TransientAuthenticationProvider implements AuthenticationProvider {

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			return new SomeTransientAuthentication();
		}

		@Override
		public boolean supports(Class<?> authentication) {
			return true;
		}

	}

	@Transient
	static class SomeTransientAuthentication extends AbstractAuthenticationToken {

		SomeTransientAuthentication() {
			super((Collection<? extends GrantedAuthority>) null);
		}

		@Override
		public Object getCredentials() {
			return null;
		}

		@Override
		public Object getPrincipal() {
			return null;
		}

	}

}
