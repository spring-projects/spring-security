package org.springframework.security.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Iterates an {@link Authentication} request through a list of {@link ReactiveAuthenticationManager}s.
 * The last successful authentication will be returned as the result.
 *
 * @author Max Batischev
 */
public class CompositeReactiveAuthenticationManager implements ReactiveAuthenticationManager {
	private final List<ReactiveAuthenticationManager> authenticationManagers;
	private final Log logger = LogFactory.getLog(this.getClass());

	public CompositeReactiveAuthenticationManager(ReactiveAuthenticationManager... authenticationManagers) {
		Assert.notNull(authenticationManagers, "authenticationManagers list cannot be null");
		this.authenticationManagers = List.of(authenticationManagers);
	}

	public CompositeReactiveAuthenticationManager(List<ReactiveAuthenticationManager> authenticationManagers) {
		Assert.notNull(authenticationManagers, "authenticationManagers list cannot be null");
		this.authenticationManagers = authenticationManagers;
	}

	@Override
	public Mono<Authentication> authenticate(Authentication authentication) {
		return Flux.fromIterable(authenticationManagers)
				.concatMapDelayError(authenticationManager ->
						authenticationManager.authenticate(authentication)
								.doOnError(logger::debug)
				)
				.next();
	}
}
