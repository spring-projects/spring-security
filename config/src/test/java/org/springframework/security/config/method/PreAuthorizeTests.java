/*
 * Copyright 2002-2015 the original author or authors.
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

package org.springframework.security.config.method;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Rob Winch
 *
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration
public class PreAuthorizeTests {

	@Autowired
	PreAuthorizeServiceImpl service;

	@After
	public void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void preAuthorizeAdminRoleDenied() {
		SecurityContextHolder.getContext()
				.setAuthentication(new TestingAuthenticationToken("user", "pass", "ROLE_USER"));
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.service::preAuthorizeAdminRole);
	}

	@Test
	public void preAuthorizeAdminRoleGranted() {
		SecurityContextHolder.getContext()
				.setAuthentication(new TestingAuthenticationToken("user", "pass", "ROLE_ADMIN"));
		this.service.preAuthorizeAdminRole();
	}

	@Test
	public void preAuthorizeContactPermissionGranted() {
		SecurityContextHolder.getContext()
				.setAuthentication(new TestingAuthenticationToken("user", "pass", "ROLE_ADMIN"));
		this.service.contactPermission(new Contact("user"));
	}

	@Test
	public void preAuthorizeContactPermissionDenied() {
		SecurityContextHolder.getContext()
				.setAuthentication(new TestingAuthenticationToken("user", "pass", "ROLE_ADMIN"));
		assertThatExceptionOfType(AccessDeniedException.class)
				.isThrownBy(() -> this.service.contactPermission(new Contact("admin")));
	}

}
