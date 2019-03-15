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

package org.springframework.security.access.intercept;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

import java.util.Collection;
import java.util.List;
import java.util.Vector;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.AfterInvocationProvider;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.core.Authentication;
import org.springframework.security.util.SimpleMethodInvocation;

/**
 * Tests {@link AfterInvocationProviderManager}.
 *
 * @author Ben Alex
 */
@SuppressWarnings("unchecked")
public class AfterInvocationProviderManagerTests {

	// ~ Methods
	// ========================================================================================================
	@Test
	public void testCorrectOperation() throws Exception {
		AfterInvocationProviderManager manager = new AfterInvocationProviderManager();
		List list = new Vector();
		list.add(new MockAfterInvocationProvider("swap1", MethodInvocation.class,
				new SecurityConfig("GIVE_ME_SWAP1")));
		list.add(new MockAfterInvocationProvider("swap2", MethodInvocation.class,
				new SecurityConfig("GIVE_ME_SWAP2")));
		list.add(new MockAfterInvocationProvider("swap3", MethodInvocation.class,
				new SecurityConfig("GIVE_ME_SWAP3")));
		manager.setProviders(list);
		assertThat(manager.getProviders()).isEqualTo(list);
		manager.afterPropertiesSet();

		List<ConfigAttribute> attr1 = SecurityConfig.createList(
				new String[] { "GIVE_ME_SWAP1" });
		List<ConfigAttribute> attr2 = SecurityConfig.createList(
				new String[] { "GIVE_ME_SWAP2" });
		List<ConfigAttribute> attr3 = SecurityConfig.createList(
				new String[] { "GIVE_ME_SWAP3" });
		List<ConfigAttribute> attr2and3 = SecurityConfig.createList(
				new String[] { "GIVE_ME_SWAP2", "GIVE_ME_SWAP3" });
		List<ConfigAttribute> attr4 = SecurityConfig.createList(
				new String[] { "NEVER_CAUSES_SWAP" });

		assertThat(manager.decide(null, new SimpleMethodInvocation(), attr1,
				"content-before-swapping")).isEqualTo("swap1");

		assertThat(manager.decide(null, new SimpleMethodInvocation(), attr2,
				"content-before-swapping")).isEqualTo("swap2");

		assertThat(manager.decide(null, new SimpleMethodInvocation(), attr3,
				"content-before-swapping")).isEqualTo("swap3");

		assertThat(manager.decide(null, new SimpleMethodInvocation(), attr4,
				"content-before-swapping")).isEqualTo("content-before-swapping");

		assertThat(manager.decide(null, new SimpleMethodInvocation(), attr2and3,
				"content-before-swapping")).isEqualTo("swap3");
	}

	@Test
	public void testRejectsEmptyProvidersList() {
		AfterInvocationProviderManager manager = new AfterInvocationProviderManager();
		List list = new Vector();

		try {
			manager.setProviders(list);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
			assertThat(true).isTrue();
		}
	}

	@Test
	public void testRejectsNonAfterInvocationProviders() {
		AfterInvocationProviderManager manager = new AfterInvocationProviderManager();
		List list = new Vector();
		list.add(new MockAfterInvocationProvider("swap1", MethodInvocation.class,
				new SecurityConfig("GIVE_ME_SWAP1")));
		list.add(Integer.valueOf(45));
		list.add(new MockAfterInvocationProvider("swap3", MethodInvocation.class,
				new SecurityConfig("GIVE_ME_SWAP3")));

		try {
			manager.setProviders(list);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
			assertThat(true).isTrue();
		}
	}

	@Test
	public void testRejectsNullProvidersList() throws Exception {
		AfterInvocationProviderManager manager = new AfterInvocationProviderManager();

		try {
			manager.afterPropertiesSet();
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
			assertThat(true).isTrue();
		}
	}

	@Test
	public void testSupportsConfigAttributeIteration() throws Exception {
		AfterInvocationProviderManager manager = new AfterInvocationProviderManager();
		List list = new Vector();
		list.add(new MockAfterInvocationProvider("swap1", MethodInvocation.class,
				new SecurityConfig("GIVE_ME_SWAP1")));
		list.add(new MockAfterInvocationProvider("swap2", MethodInvocation.class,
				new SecurityConfig("GIVE_ME_SWAP2")));
		list.add(new MockAfterInvocationProvider("swap3", MethodInvocation.class,
				new SecurityConfig("GIVE_ME_SWAP3")));
		manager.setProviders(list);
		manager.afterPropertiesSet();

		assertThat(manager.supports(new SecurityConfig("UNKNOWN_ATTRIB"))).isFalse();
		assertThat(manager.supports(new SecurityConfig("GIVE_ME_SWAP2"))).isTrue();
	}

	@Test
	public void testSupportsSecureObjectIteration() throws Exception {
		AfterInvocationProviderManager manager = new AfterInvocationProviderManager();
		List list = new Vector();
		list.add(new MockAfterInvocationProvider("swap1", MethodInvocation.class,
				new SecurityConfig("GIVE_ME_SWAP1")));
		list.add(new MockAfterInvocationProvider("swap2", MethodInvocation.class,
				new SecurityConfig("GIVE_ME_SWAP2")));
		list.add(new MockAfterInvocationProvider("swap3", MethodInvocation.class,
				new SecurityConfig("GIVE_ME_SWAP3")));
		manager.setProviders(list);
		manager.afterPropertiesSet();

		// assertFalse(manager.supports(FilterInvocation.class));
		assertThat(manager.supports(MethodInvocation.class)).isTrue();
	}

	// ~ Inner Classes
	// ==================================================================================================

	/**
	 * Always returns the constructor-defined <code>forceReturnObject</code>, provided the
	 * same configuration attribute was provided. Also stores the secure object it
	 * supports.
	 */
	private class MockAfterInvocationProvider implements AfterInvocationProvider {

		private Class secureObject;

		private ConfigAttribute configAttribute;

		private Object forceReturnObject;

		public MockAfterInvocationProvider(Object forceReturnObject, Class secureObject,
				ConfigAttribute configAttribute) {
			this.forceReturnObject = forceReturnObject;
			this.secureObject = secureObject;
			this.configAttribute = configAttribute;
		}

		public Object decide(Authentication authentication, Object object,
				Collection<ConfigAttribute> config, Object returnedObject)
						throws AccessDeniedException {
			if (config.contains(configAttribute)) {
				return forceReturnObject;
			}

			return returnedObject;
		}

		public boolean supports(Class<?> clazz) {
			return secureObject.isAssignableFrom(clazz);
		}

		public boolean supports(ConfigAttribute attribute) {
			return attribute.equals(configAttribute);
		}
	}
}
