/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.config.util;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.security.core.SpringSecurityCoreVersion;

/**
 * For computing different Spring Security versions
 */
public final class SpringSecurityVersions {

	static final Pattern SCHEMA_VERSION_PATTERN = Pattern.compile("\\d+\\.\\d+(\\.\\d+)?");

	public static String getCurrentXsdVersionFromSpringSchemas() {
		Properties properties = new Properties();
		try (InputStream is = SpringSecurityCoreVersion.class.getClassLoader()
				.getResourceAsStream("META-INF/spring.schemas")) {
			properties.load(is);
		}
		catch (IOException ex) {
			throw new RuntimeException("Could not read 'META-INF/spring.schemas'", ex);
		}

		String inPackageLocation = properties
				.getProperty("https://www.springframework.org/schema/security/spring-security.xsd");
		Matcher matcher = SCHEMA_VERSION_PATTERN.matcher(inPackageLocation);
		if (matcher.find()) {
			return matcher.group(0);
		}
		throw new IllegalStateException("Failed to find version");
	}

	private SpringSecurityVersions() {

	}

}
