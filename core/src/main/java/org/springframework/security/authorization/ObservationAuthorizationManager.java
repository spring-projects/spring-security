package org.springframework.security.authorization;

import java.util.function.Supplier;

import io.micrometer.observation.Observation;
import io.micrometer.observation.ObservationRegistry;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;

/**
 * An {@link AuthorizationManager} that observes the authorization
 *
 * @author Josh Cummings
 * @since 6.0
 */
public final class ObservationAuthorizationManager<T> implements AuthorizationManager<T> {

	private static final String OBSERVATION_NAME = "spring.security.authorization";

	private final ObservationRegistry registry;

	private final AuthorizationManager<T> delegate;

	private final AuthorizationObservationConvention<T> convention = new AuthorizationObservationConvention<>();

	public ObservationAuthorizationManager(ObservationRegistry registry, AuthorizationManager<T> delegate) {
		this.registry = registry;
		this.delegate = delegate;
	}

	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, T object) {
		AuthorizationObservationContext<T> context = new AuthorizationObservationContext<>(object);
		Supplier<Authentication> wrapped = () -> {
			context.setAuthentication(authentication.get());
			return context.getAuthentication();
		};
		Observation observation = Observation.createNotStarted(OBSERVATION_NAME, context, this.registry)
				.observationConvention(this.convention).start();
		try (Observation.Scope scope = observation.openScope()) {
			AuthorizationDecision decision = this.delegate.check(wrapped, object);
			context.setDecision(decision);
			if (decision != null && !decision.isGranted()) {
				observation.error(new AccessDeniedException("Access Denied"));
			}
			return decision;
		}
		catch (Throwable t) {
			observation.error(t);
			throw t;
		}
		finally {
			observation.stop();
		}
	}

}
