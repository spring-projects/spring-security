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

package org.springframework.security.webauthn.sample.domain.service;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.util.Base64UrlUtil;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.webauthn.authenticator.WebAuthnAuthenticatorService;
import org.springframework.security.webauthn.exception.CredentialIdNotFoundException;
import org.springframework.security.webauthn.sample.domain.entity.AuthenticatorEntity;
import org.springframework.security.webauthn.sample.domain.entity.UserEntity;
import org.springframework.security.webauthn.userdetails.WebAuthnUserDetails;
import org.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * {@inheritDoc}
 */
@Component
@Transactional
public class WebAuthnUserDetailsServiceImpl implements WebAuthnUserDetailsService, WebAuthnAuthenticatorService {

	private List<UserEntity> users = new ArrayList<>();

	/**
	 * {@inheritDoc}
	 */
	@Override
	public WebAuthnUserDetails loadUserByUsername(String username) {
		return users
				.stream()
				.filter(user -> user.getUsername().equals(username))
				.findFirst()
				.orElseThrow(() -> new UsernameNotFoundException(String.format("UserEntity with username'%s' is not found.", username)));
	}

	@Override
	public WebAuthnUserDetails loadUserByCredentialId(byte[] credentialId) {
		return users
				.stream()
				.filter(user -> user.getAuthenticators().stream().anyMatch(authenticator -> Arrays.equals(authenticator.getAttestedCredentialData().getCredentialId(), credentialId)))
				.findFirst()
				.orElseThrow(() -> new CredentialIdNotFoundException(String.format("AuthenticatorEntity with credentialId'%s' is not found.", Base64UrlUtil.encodeToString(credentialId))));
	}

	@Override
	public void addAuthenticator(String username, Authenticator authenticator) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeAuthenticator(String username, Authenticator authenticator) {
		throw new UnsupportedOperationException();
	}

	@Override
	public void removeAuthenticator(String username, byte[] credentialId) {
		throw new UnsupportedOperationException();
	}

	public UserEntity createUser(UserEntity user) {
		users.add(user);
		return user;
	}

	@Override
	public void updateCounter(byte[] credentialId, long counter) throws CredentialIdNotFoundException {

		AuthenticatorEntity authenticator = users
				.stream()
				.flatMap(user -> user.getAuthenticators().stream())
				.filter(entry -> Arrays.equals(entry.getAttestedCredentialData().getCredentialId(), credentialId))
				.findFirst()
				.orElseThrow(() -> new CredentialIdNotFoundException(String.format("AuthenticatorEntity with credentialId'%s' is not found.", Base64UrlUtil.encodeToString(credentialId))));

		authenticator.setCounter(counter);
	}

}
