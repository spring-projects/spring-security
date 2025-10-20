/*
 * Copyright 2004-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.config.annotation.authentication.configuration;

import java.util.List;

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.ObjectProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

class InitializeUserDetailsBeanManagerConfigurerTests {

	private static ObjectPostProcessor<Object> opp() {
		return new ObjectPostProcessor<>() {
			@Override
			public <O> O postProcess(O object) {
				return object;
			}
		};
	}

	@SuppressWarnings("unchecked")
	@Test
	void whenMultipleUdsAndOneResolvableCandidate_thenPrimaryIsAutoWired() throws Exception {
		ApplicationContext ctx = mock(ApplicationContext.class);
		given(ctx.getBeanNamesForType(UserDetailsService.class)).willReturn(new String[] { "udsA", "udsB" });

		PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();

		InMemoryUserDetailsManager primary = new InMemoryUserDetailsManager(
				User.withUsername("alice").passwordEncoder(encoder::encode).password("pw").roles("USER").build());
		InMemoryUserDetailsManager secondary = new InMemoryUserDetailsManager();

		ObjectProvider<UserDetailsService> udsProvider = (ObjectProvider<UserDetailsService>) mock(
				ObjectProvider.class);
		given(ctx.getBeanProvider(UserDetailsService.class)).willReturn(udsProvider);
		given(udsProvider.getIfUnique()).willReturn(primary); // container picks single
																// candidate

		// resolveBeanName(..) path
		given(ctx.getBean("udsA")).willReturn(secondary);
		given(ctx.getBean("udsB")).willReturn(primary);

		ObjectProvider<PasswordEncoder> peProvider = (ObjectProvider<PasswordEncoder>) mock(ObjectProvider.class);
		given(ctx.getBeanProvider(PasswordEncoder.class)).willReturn(peProvider);
		given(peProvider.getIfUnique()).willReturn(encoder);

		// Stub optional providers to avoid NPEs
		ObjectProvider<UserDetailsPasswordService> udpsProvider = (ObjectProvider<UserDetailsPasswordService>) mock(
				ObjectProvider.class);
		given(ctx.getBeanProvider(UserDetailsPasswordService.class)).willReturn(udpsProvider);
		given(udpsProvider.getIfAvailable()).willReturn(null);

		ObjectProvider<CompromisedPasswordChecker> cpcProvider = (ObjectProvider<CompromisedPasswordChecker>) mock(
				ObjectProvider.class);
		given(ctx.getBeanProvider(CompromisedPasswordChecker.class)).willReturn(cpcProvider);
		given(cpcProvider.getIfUnique()).willReturn(null);

		AuthenticationManagerBuilder builder = new AuthenticationManagerBuilder(opp());
		new InitializeUserDetailsBeanManagerConfigurer(ctx).new InitializeUserDetailsManagerConfigurer()
			.configure(builder);

		AuthenticationManager manager = builder.build();

		// DaoAuthenticationProvider registered
		assertThat(manager).isInstanceOf(ProviderManager.class);
		List<?> providers = ((ProviderManager) manager).getProviders();
		assertThat(providers)
			.anySatisfy((p) -> assertThat(p.getClass().getSimpleName()).isEqualTo("DaoAuthenticationProvider"));

		// Auth works with the primary UDS + encoder
		var auth = manager.authenticate(new UsernamePasswordAuthenticationToken("alice", "pw"));
		assertThat(auth.isAuthenticated()).isTrue();
	}

	@SuppressWarnings("unchecked")
	@Test
	void whenMultipleUdsAndNoSingleCandidate_thenSkipAutoWiring() throws Exception {
		ApplicationContext ctx = mock(ApplicationContext.class);
		given(ctx.getBeanNamesForType(UserDetailsService.class)).willReturn(new String[] { "udsA", "udsB" });

		ObjectProvider<UserDetailsService> udsProvider = (ObjectProvider<UserDetailsService>) mock(
				ObjectProvider.class);
		given(ctx.getBeanProvider(UserDetailsService.class)).willReturn(udsProvider);
		given(udsProvider.getIfAvailable()).willReturn(null); // ambiguous → no single
																// candidate

		// Also stub other providers to null
		ObjectProvider<PasswordEncoder> peProvider = (ObjectProvider<PasswordEncoder>) mock(ObjectProvider.class);
		given(ctx.getBeanProvider(PasswordEncoder.class)).willReturn(peProvider);
		given(peProvider.getIfUnique()).willReturn(null);

		ObjectProvider<UserDetailsPasswordService> udpsProvider = (ObjectProvider<UserDetailsPasswordService>) mock(
				ObjectProvider.class);
		given(ctx.getBeanProvider(UserDetailsPasswordService.class)).willReturn(udpsProvider);
		given(udpsProvider.getIfAvailable()).willReturn(null);

		ObjectProvider<CompromisedPasswordChecker> cpcProvider = (ObjectProvider<CompromisedPasswordChecker>) mock(
				ObjectProvider.class);
		given(ctx.getBeanProvider(CompromisedPasswordChecker.class)).willReturn(cpcProvider);
		given(cpcProvider.getIfUnique()).willReturn(null);

		AuthenticationManagerBuilder builder = new AuthenticationManagerBuilder(opp());
		new InitializeUserDetailsBeanManagerConfigurer(ctx).new InitializeUserDetailsManagerConfigurer()
			.configure(builder);

		AuthenticationManager manager = builder.build();

		// Success condition: nothing auto-registered.
		if (manager == null) {
			assertThat(manager).isNull();
		}
		else if (manager instanceof ProviderManager pm) {
			assertThat(pm.getProviders())
				.noneMatch((p) -> p.getClass().getSimpleName().equals("DaoAuthenticationProvider"));
		}
		else {
			assertThat(manager.getClass().getSimpleName()).isNotEqualTo("ProviderManager");
		}
	}

}
