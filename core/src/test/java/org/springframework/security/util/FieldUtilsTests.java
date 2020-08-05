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
package org.springframework.security.util;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.*;

/**
 * @author Luke Taylor
 */
public class FieldUtilsTests {

	@Test
	public void gettingAndSettingProtectedFieldIsSuccessful() throws Exception {
		new FieldUtils();

		Object tc = new TestClass();

		assertThat(FieldUtils.getProtectedFieldValue("protectedField", tc)).isEqualTo("x");
		assertThat(FieldUtils.getFieldValue(tc, "nested.protectedField")).isEqualTo("z");
		FieldUtils.setProtectedFieldValue("protectedField", tc, "y");
		assertThat(FieldUtils.getProtectedFieldValue("protectedField", tc)).isEqualTo("y");

		try {
			FieldUtils.getProtectedFieldValue("nonExistentField", tc);
		}
		catch (IllegalStateException expected) {
		}
	}

}

@SuppressWarnings("unused")
class TestClass {

	private String protectedField = "x";

	private Nested nested = new Nested();

}

@SuppressWarnings("unused")
class Nested {

	private String protectedField = "z";

}
