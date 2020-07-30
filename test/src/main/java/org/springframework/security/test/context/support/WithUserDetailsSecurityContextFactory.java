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

import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanNotOfRequiredTypeException;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.ReactiveUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;

/**
 * A {@link WithUserDetailsSecurityContextFactory} that works with {@link WithUserDetails}
 * .
 *
 * @author Rob Winch
 * @since 4.0
 * @see WithUserDetails
 */
final class WithUserDetailsSecurityContextFactory implements WithSecurityContextFactory<WithUserDetails> {

	private static final boolean reactorPresent = ClassUtils.isPresent("reactor.core.publisher.Mono",
			WithUserDetailsSecurityContextFactory.class.getClassLoader());

	private BeanFactory beans;

	@Autowired
	WithUserDetailsSecurityContextFactory(BeanFactory beans) {
		this.beans = beans;
	}

	@Override
	public SecurityContext createSecurityContext(WithUserDetails withUser) {
		String beanName = withUser.userDetailsServiceBeanName();
		UserDetailsService userDetailsService = findUserDetailsService(beanName);
		String username = withUser.value();
		Assert.hasLength(username, "value() must be non empty String");
		UserDetails principal = userDetailsService.loadUserByUsername(username);
		Authentication authentication = new UsernamePasswordAuthenticationToken(principal, principal.getPassword(),
				principal.getAuthorities());
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(authentication);
		return context;
	}

	private UserDetailsService findUserDetailsService(String beanName) {
		if (reactorPresent) {
			UserDetailsService reactive = findAndAdaptReactiveUserDetailsService(beanName);
			if (reactive != null) {
				return reactive;
			}
		}
		return StringUtils.hasLength(beanName) ? this.beans.getBean(beanName, UserDetailsService.class)
				: this.beans.getBean(UserDetailsService.class);
	}

	UserDetailsService findAndAdaptReactiveUserDetailsService(String beanName) {
		try {
			ReactiveUserDetailsService reactiveUserDetailsService = StringUtils.hasLength(beanName)
					? this.beans.getBean(beanName, ReactiveUserDetailsService.class)
					: this.beans.getBean(ReactiveUserDetailsService.class);
			return new ReactiveUserDetailsServiceAdapter(reactiveUserDetailsService);
		}
		catch (NoSuchBeanDefinitionException | BeanNotOfRequiredTypeException notReactive) {
			return null;
		}
	}

	private final class ReactiveUserDetailsServiceAdapter implements UserDetailsService {

		private final ReactiveUserDetailsService userDetailsService;

		private ReactiveUserDetailsServiceAdapter(ReactiveUserDetailsService userDetailsService) {
			this.userDetailsService = userDetailsService;
		}

		@Override
		public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
			return this.userDetailsService.findByUsername(username).block();
		}

	}

}
