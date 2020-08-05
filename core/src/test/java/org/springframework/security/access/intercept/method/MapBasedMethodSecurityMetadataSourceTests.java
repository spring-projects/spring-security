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
package org.springframework.security.access.intercept.method;

import static org.assertj.core.api.Assertions.assertThat;

import java.lang.reflect.Method;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;

/**
 * Tests for {@link MapBasedMethodSecurityMetadataSource}.
 *
 * @author Luke Taylor
 * @since 2.0.4
 */
public class MapBasedMethodSecurityMetadataSourceTests {

	private final List<ConfigAttribute> ROLE_A = SecurityConfig.createList("ROLE_A");

	private final List<ConfigAttribute> ROLE_B = SecurityConfig.createList("ROLE_B");

	private MapBasedMethodSecurityMetadataSource mds;

	private Method someMethodString;

	private Method someMethodInteger;

	@Before
	public void initialize() throws Exception {
		mds = new MapBasedMethodSecurityMetadataSource();
		someMethodString = MockService.class.getMethod("someMethod", String.class);
		someMethodInteger = MockService.class.getMethod("someMethod", Integer.class);
	}

	@Test
	public void wildcardedMatchIsOverwrittenByMoreSpecificMatch() {
		mds.addSecureMethod(MockService.class, "some*", ROLE_A);
		mds.addSecureMethod(MockService.class, "someMethod*", ROLE_B);
		assertThat(mds.getAttributes(someMethodInteger, MockService.class)).isEqualTo(ROLE_B);
	}

	@Test
	public void methodsWithDifferentArgumentsAreMatchedCorrectly() {
		mds.addSecureMethod(MockService.class, someMethodInteger, ROLE_A);
		mds.addSecureMethod(MockService.class, someMethodString, ROLE_B);

		assertThat(mds.getAttributes(someMethodInteger, MockService.class)).isEqualTo(ROLE_A);
		assertThat(mds.getAttributes(someMethodString, MockService.class)).isEqualTo(ROLE_B);
	}

	@SuppressWarnings("unused")
	private class MockService {

		public void someMethod(String s) {
		}

		public void someMethod(Integer i) {
		}

	}

}
