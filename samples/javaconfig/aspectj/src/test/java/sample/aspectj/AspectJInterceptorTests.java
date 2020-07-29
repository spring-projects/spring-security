/*
 * Copyright 2002-2016 the original author or authors.
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

package sample.aspectj;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;


import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import java.lang.reflect.Proxy;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = AspectjSecurityConfig.class)
public class AspectJInterceptorTests {
	private Authentication admin = new UsernamePasswordAuthenticationToken("test", "xxx",
			AuthorityUtils.createAuthorityList("ROLE_ADMIN"));
	private Authentication user = new UsernamePasswordAuthenticationToken("test", "xxx",
			AuthorityUtils.createAuthorityList("ROLE_USER"));

	@Autowired
	private Service service;

	@Autowired
	private SecuredService securedService;

	@Test
	public void publicMethod() {
		service.publicMethod();
	}

	@Test(expected = AuthenticationCredentialsNotFoundException.class)
	public void securedMethodNotAuthenticated() {
		service.secureMethod();
	}

	@Test(expected = AccessDeniedException.class)
	public void securedMethodWrongRole() {
		SecurityContextHolder.getContext().setAuthentication(admin);
		service.secureMethod();
	}

	@Test
	public void securedMethodEverythingOk() {
		SecurityContextHolder.getContext().setAuthentication(user);
		service.secureMethod();
	}

	@Test(expected = AuthenticationCredentialsNotFoundException.class)
	public void securedClassNotAuthenticated() {
		securedService.secureMethod();
	}

	@Test(expected = AccessDeniedException.class)
	public void securedClassWrongRole() {
		SecurityContextHolder.getContext().setAuthentication(admin);
		securedService.secureMethod();
	}

	@Test(expected = AccessDeniedException.class)
	public void securedClassWrongRoleOnNewedInstance() {
		SecurityContextHolder.getContext().setAuthentication(admin);
		new SecuredService().secureMethod();
	}

	@Test
	public void securedClassEverythingOk() {
		SecurityContextHolder.getContext().setAuthentication(user);
		securedService.secureMethod();
		new SecuredService().secureMethod();
	}

	// SEC-2595
	@Test
	public void notProxy() {
		assertThat(Proxy.isProxyClass(securedService.getClass())).isFalse();
	}

	@After
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}
}
