/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.core.token;

/**
 * A token issued by {@link TokenService}.
 *
 * <p>
 * It is important that the keys assigned to tokens are sufficiently randomised and
 * secured that they can serve as identifying a unique user session. Implementations of
 * {@link TokenService} are free to use encryption or encoding strategies of their choice.
 * It is strongly recommended that keys are of sufficient length to balance safety against
 * persistence cost. In relation to persistence cost, it is strongly recommended that
 * returned keys are small enough for encoding in a cookie.
 * </p>
 *
 * @author Ben Alex
 * @since 2.0.1
 */
public interface Token {

	/**
	 * Obtains the randomised, secure key assigned to this token. Presentation of this
	 * token to {@link TokenService} will always return a <code>Token</code> that is equal
	 * to the original <code>Token</code> issued for that key.
	 *
	 * @return a key with appropriate randomness and security.
	 */
	String getKey();

	/**
	 * The time the token key was initially created is available from this method. Note
	 * that a given token must never have this creation time changed. If necessary, a new
	 * token can be requested from the {@link TokenService} to replace the original token.
	 *
	 * @return the time this token key was created, in the same format as specified by
	 * {@link java.util.Date#getTime()}.
	 */
	long getKeyCreationTime();

	/**
	 * Obtains the extended information associated within the token, which was presented
	 * when the token was first created.
	 *
	 * @return the user-specified extended information, if any
	 */
	String getExtendedInformation();
}
