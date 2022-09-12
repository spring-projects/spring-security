package org.springframework.security.authentication;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;
import reactor.core.publisher.Mono;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

/**
 * An {@link ReactiveAuthenticationManager} that observes the authentication
 *
 * @author Josh Cummings
 * @since 6.0
 */
public class ObservationReactiveAuthenticationManager implements ReactiveAuthenticationManager {

	private static final String OBSERVATION_NAME = "spring.security.authentication";

	private final ObservationRegistry registry;

	private final ReactiveAuthenticationManager delegate;

	private final AuthenticationObservationConvention convention = new AuthenticationObservationConvention();

	public ObservationReactiveAuthenticationManager(ObservationRegistry registry,
			ReactiveAuthenticationManager delegate) {
		this.registry = registry;
		this.delegate = delegate;
	}

	@Override
	public Mono<Authentication> authenticate(Authentication authentication) throws AuthenticationException {
		AuthenticationObservationContext context = new AuthenticationObservationContext();
		context.setAuthenticationRequest(authentication);
		context.setAuthenticationManager(this.delegate.getClass());
		Observation observation = Observation.createNotStarted(OBSERVATION_NAME, context, this.registry)
				.observationConvention(this.convention).start();
		return this.delegate.authenticate(authentication).doOnSuccess((result) -> {
			context.setAuthenticationResult(result);
			observation.stop();
		}).doOnCancel(observation::stop).doOnError((t) -> {
			observation.error(t);
			observation.stop();
		});
	}

}
