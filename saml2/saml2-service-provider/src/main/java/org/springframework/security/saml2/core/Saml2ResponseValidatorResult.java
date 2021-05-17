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

package org.springframework.security.saml2.core;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;

import org.springframework.util.Assert;

/**
 * A result emitted from a SAML 2.0 Response validation attempt
 *
 * @author Josh Cummings
 * @since 5.4
 */
public final class Saml2ResponseValidatorResult {

	static final Saml2ResponseValidatorResult NO_ERRORS = new Saml2ResponseValidatorResult(Collections.emptyList());

	private final Collection<Saml2Error> errors;

	private Saml2ResponseValidatorResult(Collection<Saml2Error> errors) {
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
	public Collection<Saml2Error> getErrors() {
		return Collections.unmodifiableCollection(this.errors);
	}

	/**
	 * Return a new {@link Saml2ResponseValidatorResult} that contains both the given
	 * {@link Saml2Error} and the errors from the result
	 * @param error the {@link Saml2Error} to append
	 * @return a new {@link Saml2ResponseValidatorResult} for further reporting
	 */
	public Saml2ResponseValidatorResult concat(Saml2Error error) {
		Assert.notNull(error, "error cannot be null");
		Collection<Saml2Error> errors = new ArrayList<>(this.errors);
		errors.add(error);
		return failure(errors);
	}

	/**
	 * Return a new {@link Saml2ResponseValidatorResult} that contains the errors from the
	 * given {@link Saml2ResponseValidatorResult} as well as this result.
	 * @param result the {@link Saml2ResponseValidatorResult} to merge with this one
	 * @return a new {@link Saml2ResponseValidatorResult} for further reporting
	 */
	public Saml2ResponseValidatorResult concat(Saml2ResponseValidatorResult result) {
		Assert.notNull(result, "result cannot be null");
		Collection<Saml2Error> errors = new ArrayList<>(this.errors);
		errors.addAll(result.getErrors());
		return failure(errors);
	}

	/**
	 * Construct a successful {@link Saml2ResponseValidatorResult}
	 * @return an {@link Saml2ResponseValidatorResult} with no errors
	 */
	public static Saml2ResponseValidatorResult success() {
		return NO_ERRORS;
	}

	/**
	 * Construct a failure {@link Saml2ResponseValidatorResult} with the provided detail
	 * @param errors the list of errors
	 * @return an {@link Saml2ResponseValidatorResult} with the errors specified
	 */
	public static Saml2ResponseValidatorResult failure(Saml2Error... errors) {
		return failure(Arrays.asList(errors));
	}

	/**
	 * Construct a failure {@link Saml2ResponseValidatorResult} with the provided detail
	 * @param errors the list of errors
	 * @return an {@link Saml2ResponseValidatorResult} with the errors specified
	 */
	public static Saml2ResponseValidatorResult failure(Collection<Saml2Error> errors) {
		if (errors.isEmpty()) {
			return NO_ERRORS;
		}

		return new Saml2ResponseValidatorResult(errors);
	}

}
