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

package org.springframework.security.config.annotation.authorization;

/**
 * Condition under which multi-factor authentication is required.
 *
 * @author Rob Winch
 * @since 7.1
 * @see EnableMultiFactorAuthentication#when()
 */
public enum MultiFactorCondition {

	/**
	 * Require multi-factor authentication only when the user has a WebAuthn credential
	 * record registered.
	 * <p>
	 * When this condition is specified,
	 * {@link EnableMultiFactorAuthentication#authorities()} must include
	 * {@link org.springframework.security.core.authority.FactorGrantedAuthority#WEBAUTHN_AUTHORITY}.
	 * Failing to include it results in an {@link IllegalArgumentException} when the
	 * configuration is processed.
	 * <p>
	 * Using this condition also requires both a
	 * {@link org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository}
	 * Bean and a
	 * {@link org.springframework.security.web.webauthn.management.UserCredentialRepository}
	 * Bean to be published.
	 *
	 * <pre>
	 * &#64;Bean
	 * public PublicKeyCredentialUserEntityRepository userEntityRepository() {
	 *     return new InMemoryPublicKeyCredentialUserEntityRepository();
	 * }
	 *
	 * &#64;Bean
	 * public UserCredentialRepository userCredentialRepository() {
	 *     return new InMemoryUserCredentialRepository();
	 * }
	 * </pre>
	 */
	WEBAUTHN_REGISTERED

}
