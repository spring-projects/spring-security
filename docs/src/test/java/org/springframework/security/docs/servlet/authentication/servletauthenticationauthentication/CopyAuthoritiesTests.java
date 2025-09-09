package org.springframework.security.docs.servlet.authentication.servletauthenticationauthentication;

import org.junit.jupiter.api.Test;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.SecurityAssertions;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.ott.OneTimeTokenAuthentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

public class CopyAuthoritiesTests {
	@Test
	void toBuilderWhenApplyThenCopies() {
		UsernamePasswordAuthenticationToken previous = new UsernamePasswordAuthenticationToken("alice", "pass",
				AuthorityUtils.createAuthorityList("FACTOR_PASSWORD"));
		SecurityContextHolder.getContext().setAuthentication(previous);
		Authentication latest = new OneTimeTokenAuthentication("bob",
				AuthorityUtils.createAuthorityList("FACTOR_OTT"));
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		given(authenticationManager.authenticate(any())).willReturn(latest);
		Authentication authenticationRequest = new TestingAuthenticationToken("user", "pass");
		// tag::springSecurity[]
		Authentication lastestResult = authenticationManager.authenticate(authenticationRequest);
		Authentication previousResult = SecurityContextHolder.getContext().getAuthentication();
		if (previousResult != null && previousResult.isAuthenticated()) {
			lastestResult = lastestResult.toBuilder()
					.authorities((a) -> a.addAll(previous.getAuthorities()))
					.build();
		}
		// end::springSecurity[]
		SecurityAssertions.assertThat(lastestResult).hasAuthorities("FACTOR_PASSWORD", "FACTOR_OTT");
		SecurityContextHolder.clearContext();
	}
}
