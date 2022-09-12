package org.springframework.security.authentication;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * An {@link AuthenticationManager} that observes the authentication
 *
 * @author Josh Cummings
 * @since 6.0
 */
public final class ObservationAuthenticationManager implements AuthenticationManager {

	private static final String OBSERVATION_NAME = "spring.security.authentication";

	private final ObservationRegistry registry;

	private final AuthenticationManager delegate;

	private final AuthenticationObservationConvention convention = new AuthenticationObservationConvention();

	public ObservationAuthenticationManager(ObservationRegistry registry, AuthenticationManager delegate) {
		this.registry = registry;
		this.delegate = delegate;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		AuthenticationObservationContext context = new AuthenticationObservationContext();
		context.setAuthenticationRequest(authentication);
		context.setAuthenticationManager(this.delegate.getClass());
		return Observation.createNotStarted(OBSERVATION_NAME, context, this.registry)
				.observationConvention(this.convention).observe(() -> {
					Authentication result = this.delegate.authenticate(authentication);
					context.setAuthenticationResult(result);
					return result;
				});
	}

}
