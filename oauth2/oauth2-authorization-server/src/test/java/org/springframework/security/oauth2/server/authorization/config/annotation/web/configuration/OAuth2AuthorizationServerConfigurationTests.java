/*
 * Copyright 2020-2022 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration;

import java.lang.reflect.Method;

import org.junit.jupiter.api.Test;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.OrderUtils;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.util.ClassUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OAuth2AuthorizationServerConfiguration}.
 *
 * @author Joe Grandja
 */
public class OAuth2AuthorizationServerConfigurationTests {

	@Test
	public void assertOrderHighestPrecedence() {
		Method authorizationServerSecurityFilterChainMethod = ClassUtils.getMethod(
				OAuth2AuthorizationServerConfiguration.class, "authorizationServerSecurityFilterChain",
				HttpSecurity.class);
		Integer order = OrderUtils.getOrder(authorizationServerSecurityFilterChainMethod);
		assertThat(order).isEqualTo(Ordered.HIGHEST_PRECEDENCE);
	}

}
