/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.remoting.rmi;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import java.lang.reflect.Method;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.After;
import org.junit.Test;
import org.springframework.security.TargetObject;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.util.SimpleMethodInvocation;
import org.springframework.test.util.ReflectionTestUtils;

/**
 * Tests {@link ContextPropagatingRemoteInvocation} and
 * {@link ContextPropagatingRemoteInvocationFactory}.
 *
 * @author Ben Alex
 */
public class ContextPropagatingRemoteInvocationTests {

	// ~ Methods
	// ========================================================================================================
	@After
	public void tearDown() throws Exception {
		SecurityContextHolder.clearContext();
	}

	private ContextPropagatingRemoteInvocation getRemoteInvocation() throws Exception {
		Class<TargetObject> clazz = TargetObject.class;
		Method method = clazz.getMethod("makeLowerCase", new Class[] { String.class });
		MethodInvocation mi = new SimpleMethodInvocation(new TargetObject(), method,
				"SOME_STRING");

		ContextPropagatingRemoteInvocationFactory factory = new ContextPropagatingRemoteInvocationFactory();

		return (ContextPropagatingRemoteInvocation) factory.createRemoteInvocation(mi);
	}

	@Test
	public void testContextIsResetEvenIfExceptionOccurs() throws Exception {
		// Setup client-side context
		Authentication clientSideAuthentication = new UsernamePasswordAuthenticationToken(
				"rod", "koala");
		SecurityContextHolder.getContext().setAuthentication(clientSideAuthentication);

		ContextPropagatingRemoteInvocation remoteInvocation = getRemoteInvocation();

		try {
			// Set up the wrong arguments.
			remoteInvocation.setArguments(new Object[] {});
			remoteInvocation.invoke(TargetObject.class.newInstance());
			fail("Expected IllegalArgumentException");
		}
		catch (IllegalArgumentException e) {
			// expected
		}

		assertThat(
				SecurityContextHolder.getContext().getAuthentication()).withFailMessage(
						"Authentication must be null").isNull();
	}

	@Test
	public void testNormalOperation() throws Exception {
		// Setup client-side context
		Authentication clientSideAuthentication = new UsernamePasswordAuthenticationToken(
				"rod", "koala");
		SecurityContextHolder.getContext().setAuthentication(clientSideAuthentication);

		ContextPropagatingRemoteInvocation remoteInvocation = getRemoteInvocation();

		// Set to null, as ContextPropagatingRemoteInvocation already obtained
		// a copy and nulling is necessary to ensure the Context delivered by
		// ContextPropagatingRemoteInvocation is used on server-side
		SecurityContextHolder.clearContext();

		// The result from invoking the TargetObject should contain the
		// Authentication class delivered via the SecurityContextHolder
		assertThat(remoteInvocation.invoke(new TargetObject())).isEqualTo(
				"some_string org.springframework.security.authentication.UsernamePasswordAuthenticationToken false");
	}

	@Test
	public void testNullContextHolderDoesNotCauseInvocationProblems() throws Exception {
		SecurityContextHolder.clearContext(); // just to be explicit

		ContextPropagatingRemoteInvocation remoteInvocation = getRemoteInvocation();
		SecurityContextHolder.clearContext(); // unnecessary, but for
												// explicitness

		assertThat(remoteInvocation.invoke(new TargetObject())).isEqualTo(
				"some_string Authentication empty");
	}

	// SEC-1867
	@Test
	public void testNullCredentials() throws Exception {
		Authentication clientSideAuthentication = new UsernamePasswordAuthenticationToken(
				"rod", null);
		SecurityContextHolder.getContext().setAuthentication(clientSideAuthentication);

		ContextPropagatingRemoteInvocation remoteInvocation = getRemoteInvocation();
		assertThat(
				ReflectionTestUtils.getField(remoteInvocation, "credentials")).isNull();
	}
}
