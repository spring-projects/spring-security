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

package org.springframework.security.saml2;

import org.opensaml.core.Version;

import org.springframework.util.Assert;

/**
 * A Utils class that allows checking the version of the OpenSAML library in the
 * classpath.
 *
 * @author Igor Pelesić
 * @since 5.7
 */

public final class Saml2VersionUtils {

	private static final String DELIMITER = "\\.";

	private Saml2VersionUtils() {
	}

	/**
	 * Checks whether a supported OpenSAML 3 version is found on the classpath.
	 */
	public static void checkOpenSAML3VersionSupported() {
		Assert.state(getVersion().startsWith("3"), "OpenSAML version 3.x.x not found on the classpath");
	}

	/**
	 * Checks whether a supported OpenSAML 4 version is found on the classpath.
	 */
	public static void checkOpenSAML4VersionSupported() {
		Assert.state(isSaml2VersionGreaterEqual("4.1.0"),
				"OpenSAML version higher or equal to 4.1.0 not found on the classpath");
	}

	private static boolean isSaml2VersionGreaterEqual(String requiredVersion) {
		String[] splitVersion = getVersion().split(DELIMITER);
		String[] splitRequiredVersion = requiredVersion.split(DELIMITER);

		if (splitVersion.length != splitRequiredVersion.length) {
			throw new IllegalStateException("unexpected OpenSAML version");
		}

		for (int i = 0; i < splitVersion.length; i++) {
			Integer versionNumber = getVersionNumber(splitVersion[i]);
			Integer requiredVersionNumber = getVersionNumber(splitRequiredVersion[i]);
			if (versionNumber > requiredVersionNumber) {
				return true;
			}
			else if (versionNumber == requiredVersionNumber) {
				if (i == splitVersion.length - 1) {
					return true;
				}
				continue;
			}
			else {
				return false;
			}
		}

		return false;
	}

	private static String getVersion() {
		String version = Version.getVersion();
		if (version != null) {
			return version;
		}
		return Version.class.getModule().getDescriptor().version().map(Object::toString)
				.orElseThrow(() -> new IllegalStateException("cannot determine OpenSAML version"));
	}

	private static Integer getVersionNumber(String versionStr) {
		try {
			return Integer.parseInt(versionStr);
		}
		catch (NumberFormatException ex) {
			throw new IllegalStateException("could not parse OpenSAML version");
		}
	}

}
