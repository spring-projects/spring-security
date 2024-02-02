package org.springframework.security.authentication;


import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

/**
 * @author Max Batischev
 */
@ExtendWith(MockitoExtension.class)
public class CompositeReactiveAuthenticationManagerTests {

	@Mock
	private ReactiveAuthenticationManager manager1;

	@Mock
	private ReactiveAuthenticationManager manager2;

	@Mock
	private Authentication authentication;

	@Test
	void authenticateWhenFirstManagerEmptyAndSecondManagerNotEmpty() {
		when(manager1.authenticate(any())).thenReturn(Mono.empty());
		when(manager2.authenticate(any())).thenReturn(Mono.just(authentication));

		CompositeReactiveAuthenticationManager manager = new CompositeReactiveAuthenticationManager(
				manager1, manager2
		);

		assertThat(manager.authenticate(authentication).block()).isEqualTo(authentication);
	}

	@Test
	void authenticateWhenFirstManagerNotEmptyAndSecondManagerNotEmpty() {
		when(manager1.authenticate(any())).thenReturn(Mono.just(authentication));
		lenient().when(manager2.authenticate(any())).thenReturn(Mono.just(authentication));

		CompositeReactiveAuthenticationManager manager = new CompositeReactiveAuthenticationManager(
				List.of(manager1, manager2)
		);

		assertThat(manager.authenticate(authentication).block()).isEqualTo(authentication);
	}

	@Test
	void authenticateWhenSecondManagerNotEmptyAndFirstManagerThrowsException() {
		when(manager2.authenticate(any())).thenReturn(Mono.just(authentication));
		when(manager1.authenticate(any())).thenReturn(Mono.error(new AuthenticationServiceException("Error")));

		CompositeReactiveAuthenticationManager manager = new CompositeReactiveAuthenticationManager(
				manager1, manager2
		);

		assertThat(manager.authenticate(this.authentication).block()).isEqualTo(this.authentication);
	}

	@Test
	void dontAuthenticateWhenBothManagersThrowException() {
		when(manager2.authenticate(any())).thenReturn(Mono.error(new AuthenticationServiceException("Error")));
		when(manager1.authenticate(any())).thenReturn(Mono.error(new AuthenticationServiceException("Error")));

		CompositeReactiveAuthenticationManager manager = new CompositeReactiveAuthenticationManager(
				manager1, manager2
		);

		StepVerifier.create(manager.authenticate(this.authentication))
				.expectError(AuthenticationServiceException.class)
				.verify();
	}
}
