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
 * @author visweshwarganesh
 * @Created 06/20/2020 - 9:13 AM
 * RFC-7521 Assertion Framework for OAuth 2.0 Client Authentication and Authorization Grants
 * https://tools.ietf.org/html/rfc7521#section-9
 */
public interface ClientAssertionParameterNames {

	/**
	 * {@code assertion} - used in Access Token Request.
	 */
	String ASSERTION = "assertion";

	/**
	 * {@code client_assertion} - used in Access Token Request.
	 */
	String CLIENT_ASSERTION = "client_assertion";

	/**
	 * {@code client_assertion_type} - used in Access Token Request.
	 */
	String CLIENT_ASSERTION_TYPE = "client_assertion_type";
}
