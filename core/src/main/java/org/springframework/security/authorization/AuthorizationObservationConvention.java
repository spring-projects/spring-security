package org.springframework.security.authorization;

import java.util.Set;

import io.micrometer.common.KeyValues;
import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationConvention;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;

public final class AuthorizationObservationConvention
		implements ObservationConvention<AuthorizationObservationContext<?>> {

	@Override
	public KeyValues getLowCardinalityKeyValues(AuthorizationObservationContext<?> context) {
		KeyValues kvs = KeyValues.empty();
		Authentication authentication = context.getAuthentication();
		if (authentication != null) {
			String type = authentication.getAuthenticationType();
			kvs = KeyValues.of("authentication.type", type);
		}
		if (context.getDecision() != null) {
			AuthorizationDecision decision = context.getDecision();
			return kvs.and("authorization.decision", String.valueOf(decision.isGranted()));
		}
		return kvs;
	}

	@Override
	public KeyValues getHighCardinalityKeyValues(AuthorizationObservationContext<?> context) {
		KeyValues kvs = KeyValues.empty();
		Authentication authentication = context.getAuthentication();
		if (authentication != null) {
			Set<String> authorities = AuthorityUtils.authorityListToSet(authentication.getAuthorities());
			kvs = KeyValues.of("authentication.authorities", String.valueOf(authorities));
		}
		if (context.getDecision() != null) {
			AuthorizationDecision decision = context.getDecision();
			return kvs.and("authorization.decision.details", String.valueOf(decision));
		}
		return kvs;
	}

	@Override
	public boolean supportsContext(Observation.Context context) {
		return context instanceof AuthorizationObservationContext<?>;
	}

}
