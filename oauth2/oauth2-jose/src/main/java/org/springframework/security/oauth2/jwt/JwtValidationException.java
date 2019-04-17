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
package org.springframework.security.oauth2.jwt;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.util.Assert;

/**
 * An exception that results from an unsuccessful
 * {@link OAuth2TokenValidatorResult}
 *
 * @author Josh Cummings
 * @since 5.1
 */
public class JwtValidationException extends JwtException {
	private final Collection<OAuth2Error> errors;

	/**
	 * Constructs a {@link JwtValidationException} using the provided parameters
	 *
	 * While each {@link OAuth2Error} does contain an error description, this constructor
	 * can take an overarching description that encapsulates the composition of failures
	 *
	 * That said, it is appropriate to pass one of the messages from the error list in as
	 * the exception description, for example:
	 *
	 * <pre>
	 * 	if ( result.hasErrors() ) {
	 *  	Collection&lt;OAuth2Error&gt; errors = result.getErrors();
	 *  	throw new JwtValidationException(errors.iterator().next().getDescription(), errors);
	 * 	}
	 * </pre>
	 *
	 * @param message - the exception message
	 * @param errors - a list of {@link OAuth2Error}s with extra detail about the validation result
	 */
	public JwtValidationException(String message, Collection<OAuth2Error> errors) {
		super(message);

		Assert.notEmpty(errors, "errors cannot be empty");
		this.errors = new ArrayList<>(errors);
	}

	/**
	 * Return the list of {@link OAuth2Error}s associated with this exception
	 * @return the list of {@link OAuth2Error}s associated with this exception
	 */
	public Collection<OAuth2Error> getErrors() {
		return this.errors;
	}
}
