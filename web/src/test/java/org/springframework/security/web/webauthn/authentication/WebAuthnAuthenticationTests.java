/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.webauthn.authentication;

import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.TestPublicKeyCredentialUserEntity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class WebAuthnAuthenticationTests {

	@Test
	void isAuthenticatedThenTrue() {
		PublicKeyCredentialUserEntity userEntity = TestPublicKeyCredentialUserEntity.userEntity().build();
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
		WebAuthnAuthentication authentication = new WebAuthnAuthentication(userEntity, authorities);
		assertThat(authentication.isAuthenticated()).isTrue();
	}

	@Test
	void setAuthenticationWhenTrueThenException() {
		PublicKeyCredentialUserEntity userEntity = TestPublicKeyCredentialUserEntity.userEntity().build();
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
		WebAuthnAuthentication authentication = new WebAuthnAuthentication(userEntity, authorities);
		assertThatIllegalArgumentException().isThrownBy(() -> authentication.setAuthenticated(true));
	}

	@Test
	void setAuthenticationWhenFalseThenNotAuthenticated() {
		PublicKeyCredentialUserEntity userEntity = TestPublicKeyCredentialUserEntity.userEntity().build();
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
		WebAuthnAuthentication authentication = new WebAuthnAuthentication(userEntity, authorities);
		authentication.setAuthenticated(false);
		assertThat(authentication.isAuthenticated()).isFalse();
	}

}
