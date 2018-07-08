package org.springframework.security.authentication;


import org.junit.Test;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.MFAUserDetails;

import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class MultiFactorAuthenticationProviderTests {

	@Test
	public void authenticate_with_singleFactorAuthenticationAllowedOption_false_test(){
		AuthenticationProvider delegatedAuthenticationProvider = mock(AuthenticationProvider.class);
		MFAUserDetails userDetails = mock(MFAUserDetails.class);
		when(userDetails.isSingleFactorAuthenticationAllowed()).thenReturn(true);
		UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, Collections.emptyList());
		authenticationToken.setDetails(userDetails);
		when(delegatedAuthenticationProvider.supports(any())).thenReturn(true);
		when(delegatedAuthenticationProvider.authenticate(any()))
				.thenReturn(new UsernamePasswordAuthenticationToken(
						"principal",
						"credentials",
						Collections.singletonList(new SimpleGrantedAuthority("ROLE_DUMMY"))
				));

		MultiFactorAuthenticationProvider provider = new MultiFactorAuthenticationProvider(delegatedAuthenticationProvider, new MFATokenEvaluatorImpl());
		Authentication result = provider.authenticate(new UsernamePasswordAuthenticationToken("dummy", "dummy"));

		assertThat(result).isInstanceOf(MultiFactorAuthenticationToken.class);
		assertThat(result.getPrincipal()).isEqualTo("principal");
		assertThat(result.getCredentials()).isEqualTo("credentials");
		assertThat(result.getAuthorities()).isEmpty();

	}

	@Test
	public void authenticate_with_singleFactorAuthenticationAllowedOption_true_test(){
		AuthenticationProvider delegatedAuthenticationProvider = mock(AuthenticationProvider.class);
		MFAUserDetails userDetails = mock(MFAUserDetails.class);
		when(userDetails.isSingleFactorAuthenticationAllowed()).thenReturn(true);
		UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, Collections.emptyList());
		authenticationToken.setDetails(userDetails);
		when(delegatedAuthenticationProvider.supports(any())).thenReturn(true);
		when(delegatedAuthenticationProvider.authenticate(any()))
				.thenReturn(authenticationToken);

		MultiFactorAuthenticationProvider provider = new MultiFactorAuthenticationProvider(delegatedAuthenticationProvider, new MFATokenEvaluatorImpl());
		Authentication result = provider.authenticate(new UsernamePasswordAuthenticationToken("dummy", "dummy"));

		assertThat(result).isInstanceOf(UsernamePasswordAuthenticationToken.class);
		assertThat(result).isEqualTo(result);
	}

	@Test(expected = IllegalArgumentException.class)
	public void authenticate_with_invalid_AuthenticationToken_test(){
		AuthenticationProvider delegatedAuthenticationProvider = mock(AuthenticationProvider.class);
		when(delegatedAuthenticationProvider.supports(any())).thenReturn(false);

		MultiFactorAuthenticationProvider provider = new MultiFactorAuthenticationProvider(delegatedAuthenticationProvider, new MFATokenEvaluatorImpl());
		provider.authenticate(new TestingAuthenticationToken("dummy", "dummy"));
	}

}
