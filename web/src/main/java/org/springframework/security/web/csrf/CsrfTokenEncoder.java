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

package org.springframework.security.web.csrf;

import org.jspecify.annotations.Nullable;

/**
 * Interface for encoding and decoding CSRF tokens.
 *
 * Defines methods to encode a CSRF token and to decode an encoded token
 * by referencing the original unencoded token.
 *
 * This is primarily used to safely transform CSRF tokens for security purposes.
 *
 * @author Cheol Jeon
 * @since
 * @see XorCsrfTokenEncoder
 */
public interface CsrfTokenEncoder {

	String encode(String token);

	/**
	 * Decodes the encoded CSRF token using the original unencoded token.
	 * This is necessary because the decoding process requires the original token length.
	 */
	@Nullable
	String decode(String encodedToken, String originalToken);

}
