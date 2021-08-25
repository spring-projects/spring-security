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

package org.springframework.security.oauth2.client.endpoint;

import org.springframework.security.oauth2.jwt.JwtException;

/*
 * NOTE:
 * This originated in gh-9208 (JwtEncoder),
 * which is required to realize the feature in gh-8175 (JWT Client Authentication).
 * However, we decided not to merge gh-9208 as part of the 5.5.0 release
 * and instead packaged it up privately with the gh-8175 feature.
 * We MAY merge gh-9208 in a later release but that is yet to be determined.
 *
 * gh-9208 Introduce JwtEncoder
 * https://github.com/spring-projects/spring-security/pull/9208
 *
 * gh-8175 Support JWT for Client Authentication
 * https://github.com/spring-projects/spring-security/issues/8175
 */

/**
 * This exception is thrown when an error occurs while attempting to encode a JSON Web
 * Token (JWT).
 *
 * @author Joe Grandja
 * @since 5.5
 */
class JwtEncodingException extends JwtException {

	/**
	 * Constructs a {@code JwtEncodingException} using the provided parameters.
	 * @param message the detail message
	 */
	JwtEncodingException(String message) {
		super(message);
	}

	/**
	 * Constructs a {@code JwtEncodingException} using the provided parameters.
	 * @param message the detail message
	 * @param cause the root cause
	 */
	JwtEncodingException(String message, Throwable cause) {
		super(message, cause);
	}

}
