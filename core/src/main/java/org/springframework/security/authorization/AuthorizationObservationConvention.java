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

package org.springframework.security.authorization;

import io.micrometer.common.KeyValues;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationConvention;
import org.aopalliance.intercept.MethodInvocation;

import org.springframework.security.authorization.method.MethodInvocationResult;

/**
 * An {@link ObservationConvention} for translating authorizations into {@link KeyValues}.
 *
 * @author Josh Cummings
 * @since 6.0
 */
public final class AuthorizationObservationConvention
		implements ObservationConvention<AuthorizationObservationContext<?>> {

	static final String OBSERVATION_NAME = "spring.security.authorizations";

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String getName() {
		return OBSERVATION_NAME;
	}

	@Override
	public String getContextualName(AuthorizationObservationContext<?> context) {
		return "authorize " + getObjectType(context);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public KeyValues getLowCardinalityKeyValues(AuthorizationObservationContext<?> context) {
		return KeyValues.of("spring.security.authentication.type", getAuthenticationType(context))
				.and("spring.security.object", getObjectType(context))
				.and("spring.security.authorization.decision", getAuthorizationDecision(context));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public KeyValues getHighCardinalityKeyValues(AuthorizationObservationContext<?> context) {
		return KeyValues.of("spring.security.authentication.authorities", getAuthorities(context))
				.and("spring.security.authorization.decision.details", getDecisionDetails(context));
	}

	@Override
	public boolean supportsContext(Observation.Context context) {
		return context instanceof AuthorizationObservationContext<?>;
	}

	private String getAuthenticationType(AuthorizationObservationContext<?> context) {
		if (context.getAuthentication() == null) {
			return "n/a";
		}
		return context.getAuthentication().getClass().getSimpleName();
	}

	private String getObjectType(AuthorizationObservationContext<?> context) {
		if (context.getObject() == null) {
			return "unknown";
		}
		if (context.getObject() instanceof MethodInvocation) {
			return "method";
		}
		if (context.getObject() instanceof MethodInvocationResult) {
			return "method";
		}
		String className = context.getObject().getClass().getSimpleName();
		if (className.contains("Request")) {
			return "request";
		}
		if (className.contains("Message")) {
			return "message";
		}
		return className;
	}

	private String getAuthorizationDecision(AuthorizationObservationContext<?> context) {
		if (context.getDecision() == null) {
			return "unknown";
		}
		return String.valueOf(context.getDecision().isGranted());
	}

	private String getAuthorities(AuthorizationObservationContext<?> context) {
		if (context.getAuthentication() == null) {
			return "n/a";
		}
		return String.valueOf(context.getAuthentication().getAuthorities());
	}

	private String getDecisionDetails(AuthorizationObservationContext<?> context) {
		if (context.getDecision() == null) {
			return "unknown";
		}
		AuthorizationDecision decision = context.getDecision();
		return String.valueOf(decision);
	}

}
