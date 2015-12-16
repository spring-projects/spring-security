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
