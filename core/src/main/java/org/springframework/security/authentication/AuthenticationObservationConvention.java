/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.authentication;

import io.micrometer.common.KeyValues;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationConvention;
import org.jetbrains.annotations.NotNull;

import org.springframework.lang.NonNull;

/**
 * An {@link ObservationConvention} for translating authentications into
 * {@link KeyValues}.
 *
 * @author Josh Cummings
 * @since 6.0
 */
public final class AuthenticationObservationConvention
		implements ObservationConvention<AuthenticationObservationContext> {

	static final String OBSERVATION_NAME = "spring.security.authentications";

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getName() {
		return OBSERVATION_NAME;
	}

	@Override
	public String getContextualName(AuthenticationObservationContext context) {
		if (context.getAuthenticationRequest() != null) {
			String authenticationType = context.getAuthenticationRequest().getClass().getSimpleName();
			if (authenticationType.endsWith("Token")) {
				authenticationType = authenticationType.substring(0, authenticationType.lastIndexOf("Token"));
			}
			if (authenticationType.endsWith("Authentication")) {
				authenticationType = authenticationType.substring(0, authenticationType.lastIndexOf("Authentication"));
			}
			return "authenticate " + authenticationType.toLowerCase();
		}
		return "authenticate";
	}

	/**
	 * {@inheritDoc}
	 */
	@NotNull
	@Override
	public KeyValues getLowCardinalityKeyValues(@NonNull AuthenticationObservationContext context) {
		return KeyValues.of("authentication.request.type", getAuthenticationType(context))
				.and("authentication.method", getAuthenticationMethod(context))
				.and("authentication.result.type", getAuthenticationResult(context))
				.and("authentication.failure.type", getAuthenticationFailureType(context));
	}

	private String getAuthenticationType(AuthenticationObservationContext context) {
		if (context.getAuthenticationRequest() == null) {
			return "unknown";
		}
		return context.getAuthenticationRequest().getClass().getSimpleName();
	}

	private String getAuthenticationMethod(AuthenticationObservationContext context) {
		if (context.getAuthenticationManagerClass() == null) {
			return "unknown";
		}
		return context.getAuthenticationManagerClass().getSimpleName();
	}

	private String getAuthenticationResult(AuthenticationObservationContext context) {
		if (context.getAuthenticationResult() == null) {
			return "n/a";
		}
		return context.getAuthenticationResult().getClass().getSimpleName();
	}

	private String getAuthenticationFailureType(AuthenticationObservationContext context) {
		if (context.getError() == null) {
			return "n/a";
		}
		return context.getError().getClass().getSimpleName();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean supportsContext(@NotNull Observation.Context context) {
		return context instanceof AuthenticationObservationContext;
	}

}
