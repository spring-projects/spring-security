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

package org.springframework.security.integration;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.integration.multiannotation.MultiAnnotationService;
import org.springframework.security.integration.multiannotation.PreAuthorizeService;
import org.springframework.security.integration.multiannotation.SecuredService;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Luke Taylor
 */
@ContextConfiguration(locations = { "/multi-sec-annotation-app-context.xml" })
@RunWith(SpringJUnit4ClassRunner.class)
public class MultiAnnotationTests {

	private final TestingAuthenticationToken joe_a = new TestingAuthenticationToken("joe", "pass", "ROLE_A");

	private final TestingAuthenticationToken joe_b = new TestingAuthenticationToken("joe", "pass", "ROLE_B");

	@Autowired
	MultiAnnotationService service;

	@Autowired
	PreAuthorizeService preService;

	@Autowired
	SecuredService secService;

	@After
	@Before
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void preAuthorizeDeniedIsDenied() {
		SecurityContextHolder.getContext().setAuthentication(this.joe_a);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.service::preAuthorizeDenyAllMethod);
	}

	@Test
	public void preAuthorizeRoleAIsDeniedIfRoleMissing() {
		SecurityContextHolder.getContext().setAuthentication(this.joe_b);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.service::preAuthorizeHasRoleAMethod);
	}

	@Test
	public void preAuthorizeRoleAIsAllowedIfRolePresent() {
		SecurityContextHolder.getContext().setAuthentication(this.joe_a);
		this.service.preAuthorizeHasRoleAMethod();
	}

	@Test
	public void securedAnonymousIsAllowed() {
		SecurityContextHolder.getContext().setAuthentication(this.joe_a);
		this.service.securedAnonymousMethod();
	}

	@Test
	public void securedRoleAIsDeniedIfRoleMissing() {
		SecurityContextHolder.getContext().setAuthentication(this.joe_b);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.service::securedRoleAMethod);
	}

	@Test
	public void securedRoleAIsAllowedIfRolePresent() {
		SecurityContextHolder.getContext().setAuthentication(this.joe_a);
		this.service.securedRoleAMethod();
	}

	@Test
	public void preAuthorizedOnlyServiceDeniesIfRoleMissing() {
		SecurityContextHolder.getContext().setAuthentication(this.joe_b);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.preService::preAuthorizedMethod);
	}

	@Test
	public void securedOnlyRoleAServiceDeniesIfRoleMissing() {
		SecurityContextHolder.getContext().setAuthentication(this.joe_b);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.secService::securedMethod);
	}

}
