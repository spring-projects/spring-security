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

package org.springframework.security.saml2.provider.service.authentication.logout;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.function.Consumer;

import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.util.Assert;

/**
 * A result emitted from a SAML 2.0 Logout validation attempt
 *
 * @author Josh Cummings
 * @since 5.6
 */
public final class Saml2LogoutValidatorResult {

	static final Saml2LogoutValidatorResult NO_ERRORS = new Saml2LogoutValidatorResult(Collections.emptyList());

	private final Collection<Saml2Error> errors;

	private Saml2LogoutValidatorResult(Collection<Saml2Error> errors) {
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
	 * Construct a successful {@link Saml2LogoutValidatorResult}
	 * @return an {@link Saml2LogoutValidatorResult} with no errors
	 */
	public static Saml2LogoutValidatorResult success() {
		return NO_ERRORS;
	}

	/**
	 * Construct a {@link Saml2LogoutValidatorResult.Builder}, starting with the given
	 * {@code errors}.
	 *
	 * Note that a result with no errors is considered a success.
	 * @param errors
	 * @return
	 */
	public static Saml2LogoutValidatorResult.Builder withErrors(Saml2Error... errors) {
		return new Builder(errors);
	}

	public static final class Builder {

		private final Collection<Saml2Error> errors;

		private Builder(Saml2Error... errors) {
			this(Arrays.asList(errors));
		}

		private Builder(Collection<Saml2Error> errors) {
			Assert.noNullElements(errors, "errors cannot have null elements");
			this.errors = new ArrayList<>(errors);
		}

		public Builder errors(Consumer<Collection<Saml2Error>> errorsConsumer) {
			errorsConsumer.accept(this.errors);
			return this;
		}

		public Saml2LogoutValidatorResult build() {
			return new Saml2LogoutValidatorResult(this.errors);
		}

	}

}
