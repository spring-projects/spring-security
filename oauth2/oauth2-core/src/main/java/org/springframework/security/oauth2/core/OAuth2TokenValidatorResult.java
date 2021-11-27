/*
 * Copyright 2002-2018 the original author or authors.
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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import org.springframework.util.Assert;

/**
 * A result emitted from an {@link OAuth2TokenValidator} validation attempt
 *
 * @author Josh Cummings
 * @since 5.1
 */
public final class OAuth2TokenValidatorResult {

	static final OAuth2TokenValidatorResult NO_ERRORS = new OAuth2TokenValidatorResult(Collections.emptyList());

	private final Collection<OAuth2Error> errors;

	private OAuth2TokenValidatorResult(Collection<OAuth2Error> errors) {
		Assert.notNull(errors, "errors cannot be null");
		this.errors = new ArrayList<>(errors);
	}

	/**
	 * Say whether this result indicates success
	 * @return whether this result has errors
	 */
	public boolean hasErrors() {
		return !this.errors.isEmpty();
	}

	/**
	 * Return error details regarding the validation attempt
	 * @return the collection of results in this result, if any; returns an empty list
	 * otherwise
	 */
	public Collection<OAuth2Error> getErrors() {
		return this.errors;
	}

	/**
	 * Construct a successful {@link OAuth2TokenValidatorResult}
	 * @return an {@link OAuth2TokenValidatorResult} with no errors
	 */
	public static OAuth2TokenValidatorResult success() {
		return NO_ERRORS;
	}

	/**
	 * Construct a failure {@link OAuth2TokenValidatorResult} with the provided detail
	 * @param errors the list of errors
	 * @return an {@link OAuth2TokenValidatorResult} with the errors specified
	 */
	public static OAuth2TokenValidatorResult failure(OAuth2Error... errors) {
		return failure(Arrays.asList(errors));
	}

	/**
	 * Construct a failure {@link OAuth2TokenValidatorResult} with the provided detail
	 * @param errors the list of errors
	 * @return an {@link OAuth2TokenValidatorResult} with the errors specified
	 */
	public static OAuth2TokenValidatorResult failure(Collection<OAuth2Error> errors) {
		return (errors.isEmpty()) ? NO_ERRORS : new OAuth2TokenValidatorResult(errors);
	}

}
