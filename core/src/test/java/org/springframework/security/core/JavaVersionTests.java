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
package org.springframework.security.core;

import org.junit.Test;

import java.io.DataInputStream;
import java.io.InputStream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Rob Winch
 *
 */
public class JavaVersionTests {

	private static final int JDK8_CLASS_VERSION = 52;

	@Test
	public void authenticationCorrectJdkCompatibility() throws Exception {
		assertClassVersion(Authentication.class);
	}

	private void assertClassVersion(Class<?> clazz) throws Exception {
		String classResourceName = clazz.getName().replaceAll("\\.", "/") + ".class";
		try (InputStream input = Thread.currentThread().getContextClassLoader()
				.getResourceAsStream(classResourceName)) {
			DataInputStream data = new DataInputStream(input);
			data.readInt();
			data.readShort(); // minor
			int major = data.readShort();
			assertThat(major).isEqualTo(JDK8_CLASS_VERSION);
		}
	}

}
