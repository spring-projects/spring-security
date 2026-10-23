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

package org.springframework.security.web.webauthn.authentication;

import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.AuthenticatedPrincipal;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.TestPublicKeyCredentialUserEntities;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class WebAuthnAuthenticationTests {

	@Test
	void isAuthenticatedThenTrue() {
		PublicKeyCredentialUserEntity userEntity = TestPublicKeyCredentialUserEntities.userEntity().build();
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
		WebAuthnAuthentication authentication = new WebAuthnAuthentication(userEntity, authorities);
		assertThat(authentication.isAuthenticated()).isTrue();
	}

	@Test
	void setAuthenticationWhenTrueThenException() {
		PublicKeyCredentialUserEntity userEntity = TestPublicKeyCredentialUserEntities.userEntity().build();
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
		WebAuthnAuthentication authentication = new WebAuthnAuthentication(userEntity, authorities);
		assertThatIllegalArgumentException().isThrownBy(() -> authentication.setAuthenticated(true));
	}

	@Test
	void setAuthenticationWhenFalseThenNotAuthenticated() {
		PublicKeyCredentialUserEntity userEntity = TestPublicKeyCredentialUserEntities.userEntity().build();
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");
		WebAuthnAuthentication authentication = new WebAuthnAuthentication(userEntity, authorities);
		authentication.setAuthenticated(false);
		assertThat(authentication.isAuthenticated()).isFalse();
	}

	@Test
	void getNameReturnsUserEntityName() {
		PublicKeyCredentialUserEntity userEntity = TestPublicKeyCredentialUserEntities.userEntity().build();
		WebAuthnAuthentication authentication = new WebAuthnAuthentication(userEntity,
				AuthorityUtils.createAuthorityList("ROLE_USER"));
		assertThat(authentication.getName()).isEqualTo(userEntity.getName());
	}

	// gh-19202
	@Test
	void principalImplementsAuthenticatedPrincipal() {
		PublicKeyCredentialUserEntity userEntity = TestPublicKeyCredentialUserEntities.userEntity().build();
		assertThat(userEntity).isInstanceOf(AuthenticatedPrincipal.class);
		assertThat(((AuthenticatedPrincipal) userEntity).getName()).isEqualTo(userEntity.getName());
	}

	// gh-19202
	// Simulates the name-extraction logic used internally by SpringSessionBackedSessionRegistry.
	// Before the fix, AbstractAuthenticationToken falls through to toString() because
	// PublicKeyCredentialUserEntity did not implement AuthenticatedPrincipal.
	@Test
	void principalNameResolvableViaAbstractAuthenticationToken() {
		PublicKeyCredentialUserEntity userEntity = TestPublicKeyCredentialUserEntities.userEntity().build();
		AbstractAuthenticationToken wrapper = new AbstractAuthenticationToken(Collections.emptyList()) {
			@Override
			public Object getPrincipal() {
				return userEntity;
			}

			@Override
			public Object getCredentials() {
				return null;
			}
		};
		assertThat(wrapper.getName()).isEqualTo(userEntity.getName());
	}

	@Test
	void toBuilderWhenApplyThenCopies() {
		PublicKeyCredentialUserEntity alice = TestPublicKeyCredentialUserEntities.userEntity().build();
		WebAuthnAuthentication factorOne = new WebAuthnAuthentication(alice,
				AuthorityUtils.createAuthorityList("FACTOR_ONE"));
		PublicKeyCredentialUserEntity bob = TestPublicKeyCredentialUserEntities.userEntity().build();
		WebAuthnAuthentication factorTwo = new WebAuthnAuthentication(bob,
				AuthorityUtils.createAuthorityList("FACTOR_TWO"));
		WebAuthnAuthentication result = factorOne.toBuilder()
			.authorities((a) -> a.addAll(factorTwo.getAuthorities()))
			.principal(factorTwo.getPrincipal())
			.build();
		Set<String> authorities = AuthorityUtils.authorityListToSet(result.getAuthorities());
		assertThat(result.getPrincipal()).isSameAs(factorTwo.getPrincipal());
		assertThat(authorities).containsExactlyInAnyOrder("FACTOR_ONE", "FACTOR_TWO");
	}

}
