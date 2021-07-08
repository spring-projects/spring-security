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

import java.lang.reflect.Method;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;

import static org.assertj.core.api.Assertions.assertThat;

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

	@BeforeEach
	public void initialize() throws Exception {
		this.mds = new MapBasedMethodSecurityMetadataSource();
		this.someMethodString = MockService.class.getMethod("someMethod", String.class);
		this.someMethodInteger = MockService.class.getMethod("someMethod", Integer.class);
	}

	@Test
	public void wildcardedMatchIsOverwrittenByMoreSpecificMatch() {
		this.mds.addSecureMethod(MockService.class, "some*", this.ROLE_A);
		this.mds.addSecureMethod(MockService.class, "someMethod*", this.ROLE_B);
		assertThat(this.mds.getAttributes(this.someMethodInteger, MockService.class)).isEqualTo(this.ROLE_B);
	}

	@Test
	public void methodsWithDifferentArgumentsAreMatchedCorrectly() {
		this.mds.addSecureMethod(MockService.class, this.someMethodInteger, this.ROLE_A);
		this.mds.addSecureMethod(MockService.class, this.someMethodString, this.ROLE_B);
		assertThat(this.mds.getAttributes(this.someMethodInteger, MockService.class)).isEqualTo(this.ROLE_A);
		assertThat(this.mds.getAttributes(this.someMethodString, MockService.class)).isEqualTo(this.ROLE_B);
	}

	@SuppressWarnings("unused")
	private class MockService {

		public void someMethod(String s) {
		}

		public void someMethod(Integer i) {
		}

	}

}
