package org.springframework.security.authentication;

import io.micrometer.common.KeyValues;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationConvention;

public final class AuthenticationObservationConvention
		implements ObservationConvention<AuthenticationObservationContext> {

	@Override
	public KeyValues getLowCardinalityKeyValues(AuthenticationObservationContext context) {
		KeyValues kvs = KeyValues.empty();
		if (context.getAuthenticationRequest() != null) {
			kvs = kvs.and("authentication.request.type", context.getAuthenticationRequest().getAuthenticationType());
		}
		if (context.getAuthenticationManager() != null) {
			kvs = kvs.and("authentication.method", context.getAuthenticationManager().getSimpleName());
		}
		if (context.getAuthenticationResult() != null) {
			kvs = kvs.and("authentication.result.type", context.getAuthenticationResult().getAuthenticationType());
		}
		if (context.getError().isPresent()) {
			kvs = kvs.and("authentication.failure.type", context.getError().get().getClass().getSimpleName());
		}
		return kvs;
	}

	@Override
	public boolean supportsContext(Observation.Context context) {
		return context instanceof AuthenticationObservationContext;
	}

}
