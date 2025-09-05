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
package org.springframework.security.oauth2.server.authorization.oidc.authentication;

import java.util.Collections;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link OidcUserInfoAuthenticationToken}.
 *
 * @author Steve Riesenberg
 */
public class OidcUserInfoAuthenticationTokenTests {

	@Test
	public void constructorWhenPrincipalNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new OidcUserInfoAuthenticationToken(null))
			.withMessage("principal cannot be null");
	}

	@Test
	public void constructorWhenPrincipalProvidedThenCreated() {
		UsernamePasswordAuthenticationToken principal = new UsernamePasswordAuthenticationToken(null, null);
		OidcUserInfoAuthenticationToken authentication = new OidcUserInfoAuthenticationToken(principal);
		assertThat(authentication.getPrincipal()).isEqualTo(principal);
		assertThat(authentication.getUserInfo()).isNull();
		assertThat(authentication.isAuthenticated()).isFalse();
	}

	@Test
	public void constructorWhenPrincipalAndUserInfoProvidedThenCreated() {
		UsernamePasswordAuthenticationToken principal = new UsernamePasswordAuthenticationToken(null, null);
		OidcUserInfo userInfo = new OidcUserInfo(Collections.singletonMap(StandardClaimNames.SUB, "user"));
		OidcUserInfoAuthenticationToken authentication = new OidcUserInfoAuthenticationToken(principal, userInfo);
		assertThat(authentication.getPrincipal()).isEqualTo(principal);
		assertThat(authentication.getUserInfo()).isEqualTo(userInfo);
		assertThat(authentication.isAuthenticated()).isTrue();
	}

}
