/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.oauth2.core;

/**
 * Implementations of this interface are responsible for &quot;verifying&quot; the
 * validity and/or constraints of the attributes contained in an OAuth 2.0 Token.
 *
 * @author Joe Grandja
 * @author Josh Cummings
 * @since 5.1
 */
@FunctionalInterface
public interface OAuth2TokenValidator<T extends AbstractOAuth2Token> {

	/**
	 * Verify the validity and/or constraints of the provided OAuth 2.0 Token.
	 * @param token an OAuth 2.0 token
	 * @return OAuth2TokenValidationResult the success or failure detail of the validation
	 */
	OAuth2TokenValidatorResult validate(T token);

}
