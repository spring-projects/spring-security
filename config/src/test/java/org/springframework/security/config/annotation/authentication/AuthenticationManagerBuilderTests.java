/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.config.annotation.authentication;

import java.util.Arrays;
import java.util.Properties;

import org.junit.Rule;
import org.junit.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.authentication.configuration.EnableGlobalAuthentication;
import org.springframework.security.config.annotation.configuration.ObjectPostProcessorConfiguration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated;

/**
 * @author Rob Winch
 */
public class AuthenticationManagerBuilderTests {

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired(required = false)
	MockMvc mockMvc;

	@Test
	public void buildWhenAddAuthenticationProviderThenDoesNotPerformRegistration() throws Exception {
		ObjectPostProcessor<Object> opp = mock(ObjectPostProcessor.class);
		AuthenticationProvider provider = mock(AuthenticationProvider.class);

		AuthenticationManagerBuilder builder = new AuthenticationManagerBuilder(opp);
		builder.authenticationProvider(provider);
		builder.build();

		verify(opp, never()).postProcess(provider);
	}

	// https://github.com/spring-projects/spring-security-javaconfig/issues/132
	@Test
	public void customAuthenticationEventPublisherWithWeb() throws Exception {
		ObjectPostProcessor<Object> opp = mock(ObjectPostProcessor.class);
		AuthenticationEventPublisher aep = mock(AuthenticationEventPublisher.class);
		given(opp.postProcess(any())).willAnswer((a) -> a.getArgument(0));
		AuthenticationManager am = new AuthenticationManagerBuilder(opp).authenticationEventPublisher(aep)
				.inMemoryAuthentication().and().build();

		try {
			am.authenticate(new UsernamePasswordAuthenticationToken("user", "password"));
		}
		catch (AuthenticationException success) {
		}

		verify(aep).publishAuthenticationFailure(any(), any());
	}

	@Test
	public void getAuthenticationManagerWhenGlobalPasswordEncoderBeanThenUsed() throws Exception {
		this.spring.register(PasswordEncoderGlobalConfig.class).autowire();
		AuthenticationManager manager = this.spring.getContext().getBean(AuthenticationConfiguration.class)
				.getAuthenticationManager();

		Authentication auth = manager.authenticate(new UsernamePasswordAuthenticationToken("user", "password"));

		assertThat(auth.getName()).isEqualTo("user");
		assertThat(auth.getAuthorities()).extracting(GrantedAuthority::getAuthority).containsOnly("ROLE_USER");
	}

	@Test
	public void getAuthenticationManagerWhenProtectedPasswordEncoderBeanThenUsed() throws Exception {
		this.spring.register(PasswordEncoderGlobalConfig.class).autowire();
		AuthenticationManager manager = this.spring.getContext().getBean(AuthenticationConfiguration.class)
				.getAuthenticationManager();

		Authentication auth = manager.authenticate(new UsernamePasswordAuthenticationToken("user", "password"));

		assertThat(auth.getName()).isEqualTo("user");
		assertThat(auth.getAuthorities()).extracting(GrantedAuthority::getAuthority).containsOnly("ROLE_USER");
	}

	@Test
	public void authenticationManagerWhenMultipleProvidersThenWorks() throws Exception {
		this.spring.register(MultiAuthenticationProvidersConfig.class).autowire();

		this.mockMvc.perform(formLogin()).andExpect(authenticated().withUsername("user").withRoles("USER"));

		this.mockMvc.perform(formLogin().user("admin"))
				.andExpect(authenticated().withUsername("admin").withRoles("USER", "ADMIN"));
	}

	@Test
	public void buildWhenAuthenticationProviderThenIsConfigured() throws Exception {
		ObjectPostProcessor<Object> opp = mock(ObjectPostProcessor.class);
		AuthenticationProvider provider = mock(AuthenticationProvider.class);

		AuthenticationManagerBuilder builder = new AuthenticationManagerBuilder(opp);
		builder.authenticationProvider(provider);
		builder.build();

		assertThat(builder.isConfigured()).isTrue();
	}

	@Test
	public void buildWhenParentThenIsConfigured() throws Exception {
		ObjectPostProcessor<Object> opp = mock(ObjectPostProcessor.class);
		AuthenticationManager parent = mock(AuthenticationManager.class);

		AuthenticationManagerBuilder builder = new AuthenticationManagerBuilder(opp);
		builder.parentAuthenticationManager(parent);
		builder.build();

		assertThat(builder.isConfigured()).isTrue();
	}

	@Test
	public void buildWhenNotConfiguredThenIsConfiguredFalse() throws Exception {
		ObjectPostProcessor<Object> opp = mock(ObjectPostProcessor.class);

		AuthenticationManagerBuilder builder = new AuthenticationManagerBuilder(opp);
		builder.build();

		assertThat(builder.isConfigured()).isFalse();
	}

	public void buildWhenUserFromProperties() throws Exception {
		this.spring.register(UserFromPropertiesConfig.class).autowire();

		this.mockMvc.perform(formLogin().user("joe", "joespassword"))
				.andExpect(authenticated().withUsername("joe").withRoles("USER"));
	}

	@EnableWebSecurity
	static class MultiAuthenticationProvidersConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.inMemoryAuthentication().withUser(PasswordEncodedUser.user()).and().inMemoryAuthentication()
					.withUser(PasswordEncodedUser.admin());
		}

	}

	@EnableWebSecurity
	static class PasswordEncoderGlobalConfig extends WebSecurityConfigurerAdapter {

		@Autowired
		void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
				.withUser("user").password("password").roles("USER");
			// @formatter:on
		}

		@Bean
		PasswordEncoder passwordEncoder() {
			return NoOpPasswordEncoder.getInstance();
		}

	}

	@EnableWebSecurity
	static class PasswordEncoderConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			// @formatter:off
			auth
				.inMemoryAuthentication()
				.withUser("user").password("password").roles("USER");
			// @formatter:on
		}

		@Bean
		PasswordEncoder passwordEncoder() {
			return NoOpPasswordEncoder.getInstance();
		}

	}

	@Configuration
	@EnableGlobalAuthentication
	@Import(ObjectPostProcessorConfiguration.class)
	static class UserFromPropertiesConfig {

		@Value("classpath:org/springframework/security/config/users.properties")
		Resource users;

		@Bean
		AuthenticationManager authenticationManager() throws Exception {
			return new ProviderManager(Arrays.asList(authenticationProvider()));
		}

		@Bean
		AuthenticationProvider authenticationProvider() throws Exception {
			DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
			provider.setUserDetailsService(userDetailsService());
			return provider;
		}

		@Bean
		UserDetailsService userDetailsService() throws Exception {
			Properties properties = new Properties();
			properties.load(this.users.getInputStream());
			return new InMemoryUserDetailsManager(properties);
		}

	}

}
