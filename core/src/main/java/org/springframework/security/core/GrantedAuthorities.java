/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.core;

/**
 * Constants for {@link GrantedAuthority}.
 *
 * @author Rob Winch
 * @since 7.0
 */
public final class GrantedAuthorities {

	/**
	 * The standard {@link GrantedAuthority#getAuthority()} that indicates that OAuth2
	 * Authorization Code was used to authenticate.
	 */
	public static final String FACTOR_AUTHORIZATION_CODE_AUTHORITY = "FACTOR_AUTHORIZATION_CODE";

	/**
	 * The standard {@link GrantedAuthority#getAuthority()} that indicates that bearer
	 * authentication was used to authenticate.
	 */
	public static final String FACTOR_BEARER_AUTHORITY = "FACTOR_BEARER";

	/**
	 * The standard {@link GrantedAuthority#getAuthority()} that indicates that CAS was
	 * used to authenticate.
	 */
	public static final String FACTOR_CAS_AUTHORITY = "FACTOR_CAS";

	/**
	 * The standard {@link GrantedAuthority#getAuthority()} that indicates that one time
	 * token was used to authenticate.
	 */
	public static final String FACTOR_OTT_AUTHORITY = "FACTOR_OTT";

	/**
	 * The standard {@link GrantedAuthority#getAuthority()} that indicates that a password
	 * was used to authenticate.
	 */
	public static final String FACTOR_PASSWORD_AUTHORITY = "FACTOR_PASSWORD";

	/**
	 * The standard {@link GrantedAuthority#getAuthority()} that indicates that SAML was
	 * used to authenticate.
	 */
	public static final String FACTOR_SAML_RESPONSE_AUTHORITY = "FACTOR_SAML_RESPONSE";

	/**
	 * The standard {@link GrantedAuthority#getAuthority()} that indicates that WebAuthn
	 * was used to authenticate.
	 */
	public static final String FACTOR_WEBAUTHN_AUTHORITY = "FACTOR_WEBAUTHN";

	/**
	 * The standard {@link GrantedAuthority#getAuthority()} that indicates that X509 was
	 * used to authenticate.
	 */
	public static final String FACTOR_X509_AUTHORITY = "FACTOR_X509";

	private GrantedAuthorities() {
	}

}
