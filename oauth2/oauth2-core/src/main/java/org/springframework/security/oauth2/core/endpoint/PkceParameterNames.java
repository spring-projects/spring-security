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
package org.springframework.security.oauth2.core.endpoint;

/**
 * Standard parameter names defined in the OAuth Parameters Registry
 * and used by the authorization endpoint and token endpoint.
 *
 * @author Stephen Doxsee
 * @author Kevin Bolduc
 * @since 5.2
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc7636#section-6.1">6.1 OAuth Parameters Registry</a>
 */
public interface PkceParameterNames {

	/**
	 * {@code code_challenge} - used in Authorization Request.
	 */
	String CODE_CHALLENGE = "code_challenge";

	/**
	 * {@code code_challenge_method} - used in Authorization Request.
	 */
	String CODE_CHALLENGE_METHOD = "code_challenge_method";

	/**
	 * {@code code_verifier} - used in Token Request.
	 */
	String CODE_VERIFIER = "code_verifier";
}
