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
package org.springframework.security.acls.domain;


import java.util.Arrays;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.security.acls.model.Acl;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 *
 * @author Rob Winch
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class AclAuthorizationStrategyImplTests {
	@Mock
	Acl acl;
	GrantedAuthority authority;
	AclAuthorizationStrategyImpl strategy;

	@Before
	public void setup() {
		authority = new SimpleGrantedAuthority("ROLE_AUTH");
		TestingAuthenticationToken authentication = new TestingAuthenticationToken("foo", "bar", Arrays.asList(authority));
		authentication.setAuthenticated(true);
		SecurityContextHolder.getContext().setAuthentication(authentication);
	}

	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	// gh-4085
	@Test
	public void securityCheckWhenCustomAuthorityThenNameIsUsed() {
		strategy = new AclAuthorizationStrategyImpl(new CustomAuthority());
		strategy.securityCheck(acl, AclAuthorizationStrategy.CHANGE_GENERAL);
	}

	@SuppressWarnings("serial")
	class CustomAuthority implements GrantedAuthority {
		@Override
		public String getAuthority() {
			return authority.getAuthority();
		}
	}
}
