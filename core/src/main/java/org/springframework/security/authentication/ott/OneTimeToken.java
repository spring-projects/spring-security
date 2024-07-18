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

package org.springframework.security.authentication.ott;

import java.time.Instant;

/**
 * Represents a one-time use token with an associated username and expiration time.
 *
 * @author Marcus da Coregio
 * @since 6.4
 */
public interface OneTimeToken {

	/**
	 * @return the one-time token value, never {@code null}
	 */
	String getTokenValue();

	/**
	 * @return the username associated with this token, never {@code null}
	 */
	String getUsername();

	/**
	 * @return the expiration time of the token
	 */
	Instant getExpiresAt();

}
