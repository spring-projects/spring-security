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
package org.springframework.security.test.context.support;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import reactor.core.publisher.Mono;

import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanNotOfRequiredTypeException;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class WithUserDetailsSecurityContextFactoryTests {

	@Mock
	private ReactiveUserDetailsService reactiveUserDetailsService;

	@Mock
	private UserDetailsService userDetailsService;

	@Mock
	private UserDetails userDetails;

	@Mock
	private BeanFactory beans;

	@Mock
	private WithUserDetails withUserDetails;

	private WithUserDetailsSecurityContextFactory factory;

	@Before
	public void setup() {
		this.factory = new WithUserDetailsSecurityContextFactory(this.beans);
	}

	@Test(expected = IllegalArgumentException.class)
	public void createSecurityContextNullValue() {
		this.factory.createSecurityContext(this.withUserDetails);
	}

	@Test(expected = IllegalArgumentException.class)
	public void createSecurityContextEmptyValue() {

		when(this.withUserDetails.value()).thenReturn("");
		this.factory.createSecurityContext(this.withUserDetails);
	}

	@Test
	public void createSecurityContextWithExistingUser() {
		String username = "user";
		when(this.beans.getBean(ReactiveUserDetailsService.class)).thenThrow(new NoSuchBeanDefinitionException(""));
		when(this.beans.getBean(UserDetailsService.class)).thenReturn(this.userDetailsService);
		when(this.withUserDetails.value()).thenReturn(username);
		when(this.userDetailsService.loadUserByUsername(username)).thenReturn(this.userDetails);

		SecurityContext context = this.factory.createSecurityContext(this.withUserDetails);
		assertThat(context.getAuthentication()).isInstanceOf(UsernamePasswordAuthenticationToken.class);
		assertThat(context.getAuthentication().getPrincipal()).isEqualTo(this.userDetails);
		verify(this.beans).getBean(UserDetailsService.class);
	}

	// gh-3346
	@Test
	public void createSecurityContextWithUserDetailsServiceName() {
		String beanName = "secondUserDetailsServiceBean";
		String username = "user";
		when(this.beans.getBean(beanName, ReactiveUserDetailsService.class)).thenThrow(
				new BeanNotOfRequiredTypeException("", ReactiveUserDetailsService.class, UserDetailsService.class));
		when(this.withUserDetails.value()).thenReturn(username);
		when(this.withUserDetails.userDetailsServiceBeanName()).thenReturn(beanName);
		when(this.userDetailsService.loadUserByUsername(username)).thenReturn(this.userDetails);
		when(this.beans.getBean(beanName, UserDetailsService.class)).thenReturn(this.userDetailsService);

		SecurityContext context = this.factory.createSecurityContext(this.withUserDetails);
		assertThat(context.getAuthentication()).isInstanceOf(UsernamePasswordAuthenticationToken.class);
		assertThat(context.getAuthentication().getPrincipal()).isEqualTo(this.userDetails);
		verify(this.beans).getBean(beanName, UserDetailsService.class);
	}

	@Test
	public void createSecurityContextWithReactiveUserDetailsService() {
		String username = "user";
		when(this.withUserDetails.value()).thenReturn(username);
		when(this.beans.getBean(ReactiveUserDetailsService.class)).thenReturn(this.reactiveUserDetailsService);
		when(this.reactiveUserDetailsService.findByUsername(username)).thenReturn(Mono.just(this.userDetails));

		SecurityContext context = this.factory.createSecurityContext(this.withUserDetails);
		assertThat(context.getAuthentication()).isInstanceOf(UsernamePasswordAuthenticationToken.class);
		assertThat(context.getAuthentication().getPrincipal()).isEqualTo(this.userDetails);
		verify(this.beans).getBean(ReactiveUserDetailsService.class);
	}

	@Test
	public void createSecurityContextWithReactiveUserDetailsServiceAndBeanName() {
		String beanName = "secondUserDetailsServiceBean";
		String username = "user";
		when(this.withUserDetails.value()).thenReturn(username);
		when(this.withUserDetails.userDetailsServiceBeanName()).thenReturn(beanName);
		when(this.beans.getBean(beanName, ReactiveUserDetailsService.class))
				.thenReturn(this.reactiveUserDetailsService);
		when(this.reactiveUserDetailsService.findByUsername(username)).thenReturn(Mono.just(this.userDetails));

		SecurityContext context = this.factory.createSecurityContext(this.withUserDetails);
		assertThat(context.getAuthentication()).isInstanceOf(UsernamePasswordAuthenticationToken.class);
		assertThat(context.getAuthentication().getPrincipal()).isEqualTo(this.userDetails);
		verify(this.beans).getBean(beanName, ReactiveUserDetailsService.class);
	}

}
