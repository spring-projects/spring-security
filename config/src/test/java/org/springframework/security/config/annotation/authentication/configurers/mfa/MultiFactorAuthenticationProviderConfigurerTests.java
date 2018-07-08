package org.springframework.security.config.annotation.authentication.configurers.mfa;

import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.MFATokenEvaluator;
import org.springframework.security.authentication.MultiFactorAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.ProviderManagerBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.security.config.annotation.authentication.configurers.mfa.MultiFactorAuthenticationProviderConfigurer.multiFactorAuthenticationProvider;

public class MultiFactorAuthenticationProviderConfigurerTests {

	@Test
	public void test(){
		AuthenticationProvider delegatedAuthenticationProvider = mock(AuthenticationProvider.class);
		MFATokenEvaluator mfaTokenEvaluator = mock(MFATokenEvaluator.class);
		MultiFactorAuthenticationProviderConfigurer configurer
				= multiFactorAuthenticationProvider(delegatedAuthenticationProvider);
		configurer.mfaTokenEvaluator(mfaTokenEvaluator);
		ProviderManagerBuilder providerManagerBuilder = mock(ProviderManagerBuilder.class);
		configurer.configure(providerManagerBuilder);
		ArgumentCaptor<AuthenticationProvider> argumentCaptor = ArgumentCaptor.forClass(AuthenticationProvider.class);
		verify(providerManagerBuilder).authenticationProvider(argumentCaptor.capture());
		MultiFactorAuthenticationProvider authenticationProvider = (MultiFactorAuthenticationProvider)argumentCaptor.getValue();

		assertThat(authenticationProvider.getAuthenticationProvider()).isEqualTo(delegatedAuthenticationProvider);
		assertThat(authenticationProvider.getMFATokenEvaluator()).isEqualTo(mfaTokenEvaluator);
	}
}
