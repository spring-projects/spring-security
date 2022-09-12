package org.springframework.security.authorization;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;
import reactor.core.publisher.Mono;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;

/**
 * An {@link ReactiveAuthorizationManager} that observes the authentication
 *
 * @author Josh Cummings
 * @since 6.0
 */
public final class ObservationReactiveAuthorizationManager<T> implements ReactiveAuthorizationManager<T> {

	private static final String OBSERVATION_NAME = "spring.security.authorization";

	private final ObservationRegistry registry;

	private final ReactiveAuthorizationManager<T> delegate;

	private final AuthorizationObservationConvention<T> convention = new AuthorizationObservationConvention<>();

	public ObservationReactiveAuthorizationManager(ObservationRegistry registry,
			ReactiveAuthorizationManager<T> delegate) {
		this.registry = registry;
		this.delegate = delegate;
	}

	@Override
	public Mono<AuthorizationDecision> check(Mono<Authentication> authentication, T object) {
		AuthorizationObservationContext<T> context = new AuthorizationObservationContext<>(object);
		Mono<Authentication> wrapped = authentication.map((auth) -> {
			context.setAuthentication(auth);
			return context.getAuthentication();
		});
		Observation observation = Observation.createNotStarted(OBSERVATION_NAME, context, this.registry)
				.observationConvention(this.convention).start();
		return this.delegate.check(wrapped, object).doOnSuccess((decision) -> {
			context.setDecision(decision);
			if (decision == null || !decision.isGranted()) {
				observation.error(new AccessDeniedException("Access Denied"));
			}
			observation.stop();
		}).doOnCancel(observation::stop).doOnError((t) -> {
			observation.error(t);
			observation.stop();
		});
	}

}
