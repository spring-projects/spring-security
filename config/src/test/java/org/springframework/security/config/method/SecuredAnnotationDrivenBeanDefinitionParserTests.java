/*
 * Copyright 2002-2022 the original author or authors.
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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.annotation.BusinessService;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.ConfigTestUtils;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Ben Alex
 */
public class SecuredAnnotationDrivenBeanDefinitionParserTests {

	private InMemoryXmlApplicationContext appContext;

	private BusinessService target;

	@BeforeEach
	public void loadContext() {
		SecurityContextHolder.clearContext();
		this.appContext = new InMemoryXmlApplicationContext(
				"<b:bean id='target' class='org.springframework.security.access.annotation.BusinessServiceImpl'/>"
						+ "<global-method-security secured-annotations='enabled'/>"
						+ ConfigTestUtils.AUTH_PROVIDER_XML);
		this.target = (BusinessService) this.appContext.getBean("target");
	}

	@AfterEach
	public void closeAppContext() {
		if (this.appContext != null) {
			this.appContext.close();
		}
		SecurityContextHolder.clearContext();
	}

	@Test
	public void targetShouldPreventProtectedMethodInvocationWithNoContext() {
		assertThatExceptionOfType(AuthenticationCredentialsNotFoundException.class)
				.isThrownBy(this.target::someUserMethod1);
	}

	@Test
	public void targetShouldAllowProtectedMethodInvocationWithCorrectRole() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.authenticated("Test",
				"Password", AuthorityUtils.createAuthorityList("ROLE_USER"));
		SecurityContextHolder.getContext().setAuthentication(token);
		this.target.someUserMethod1();
	}

	@Test
	public void targetShouldPreventProtectedMethodInvocationWithIncorrectRole() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.authenticated("Test",
				"Password", AuthorityUtils.createAuthorityList("ROLE_SOMEOTHER"));
		SecurityContextHolder.getContext().setAuthentication(token);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.target::someAdminMethod);
	}

	// SEC-1387
	@Test
	public void targetIsSerializableBeforeUse() throws Exception {
		BusinessService chompedTarget = (BusinessService) serializeAndDeserialize(this.target);
		assertThatExceptionOfType(AuthenticationCredentialsNotFoundException.class)
				.isThrownBy(chompedTarget::someAdminMethod);
	}

	@Test
	public void targetIsSerializableAfterUse() throws Exception {
		assertThatExceptionOfType(AuthenticationCredentialsNotFoundException.class)
				.isThrownBy(this.target::someAdminMethod);
		SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken("u", "p", "ROLE_A"));
		BusinessService chompedTarget = (BusinessService) serializeAndDeserialize(this.target);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(chompedTarget::someAdminMethod);
	}

	private Object serializeAndDeserialize(Object o) throws IOException, ClassNotFoundException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(baos);
		oos.writeObject(o);
		oos.flush();
		baos.flush();
		byte[] bytes = baos.toByteArray();
		ByteArrayInputStream is = new ByteArrayInputStream(bytes);
		ObjectInputStream ois = new ObjectInputStream(is);
		Object o2 = ois.readObject();
		return o2;
	}

}
