package org.springframework.security.web.server.csrf;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.Mockito.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.web.server.WebFilterChain;

import reactor.core.publisher.Mono;

/**
 * @author Eric Deandrea
 * @since 5.1
 */
@RunWith(MockitoJUnitRunner.class)
public class CsrfServerLogoutHandlerTests {
	@Mock
	private ServerCsrfTokenRepository csrfTokenRepository;

	@Mock
	private WebFilterChain filterChain;

	private MockServerWebExchange exchange;

	private WebFilterExchange filterExchange;

	private CsrfServerLogoutHandler handler;

	@Before
	public void setup() {
		this.exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());
		this.filterExchange = new WebFilterExchange(this.exchange, this.filterChain);
		this.handler = new CsrfServerLogoutHandler(this.csrfTokenRepository);
		when(this.csrfTokenRepository.saveToken(this.exchange, null)).thenReturn(Mono.empty());
	}

	@Test
	public void constructorNullCsrfTokenRepository() {
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> new CsrfServerLogoutHandler(null))
				.withMessage("csrfTokenRepository cannot be null")
				.withNoCause();
	}

	@Test
	public void logoutRemovesCsrfToken() {
		this.handler.logout(
				this.filterExchange,
				new TestingAuthenticationToken("user", "password", "ROLE_USER")).block();

		verify(this.csrfTokenRepository).saveToken(this.exchange, null);
	}
}
