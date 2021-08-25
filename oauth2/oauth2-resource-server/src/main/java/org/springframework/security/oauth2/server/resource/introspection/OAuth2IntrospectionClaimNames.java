/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.oauth2.server.resource.introspection;

import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;

/**
 * The names of the &quot;Introspection Claims&quot; defined by an
 * <a target="_blank" href="https://tools.ietf.org/html/rfc7662#section-2.2">Introspection
 * Response</a>.
 *
 * @deprecated Use {@link OAuth2TokenIntrospectionClaimNames} instead
 * @author Josh Cummings
 * @since 5.2
 */
@Deprecated
public interface OAuth2IntrospectionClaimNames extends OAuth2TokenIntrospectionClaimNames {

	/**
	 * {@code exp} - A timestamp indicating when the token expires
	 * @deprecated use {@link #EXP} instead
	 */
	String EXPIRES_AT = EXP;

	/**
	 * {@code iat} - A timestamp indicating when the token was issued
	 * @deprecated use {@link #IAT} instead
	 */
	String ISSUED_AT = IAT;

	/**
	 * {@code nbf} - A timestamp indicating when the token is not to be used before
	 * @deprecated use {@link #NBF} instead
	 */
	String NOT_BEFORE = NBF;

	/**
	 * {@code sub} - Usually a machine-readable identifier of the resource owner who
	 * authorized the token
	 * @deprecated use {@link #SUB} instead
	 */
	String SUBJECT = SUB;

	/**
	 * {@code aud} - The intended audience for the token
	 * @deprecated use {@link #AUD} instead
	 */
	String AUDIENCE = AUD;

	/**
	 * {@code iss} - The issuer of the token
	 * @deprecated use {@link #ISS} instead
	 */
	String ISSUER = ISS;

}
