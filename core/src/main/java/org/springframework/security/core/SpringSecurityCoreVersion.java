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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.SpringVersion;

/**
 * Internal class used for checking version compatibility in a deployed application.
 *
 * @author Luke Taylor
 * @author Rob Winch
 */
public class SpringSecurityCoreVersion {
	private static final String DISABLE_CHECKS = SpringSecurityCoreVersion.class.getName()
			.concat(".DISABLE_CHECKS");

	private static final Log logger = LogFactory.getLog(SpringSecurityCoreVersion.class);

	/**
	 * Global Serialization value for Spring Security classes.
	 *
	 * N.B. Classes are not intended to be serializable between different versions. See
	 * SEC-1709 for why we still need a serial version.
	 */
	public static final long SERIAL_VERSION_UID = 420L;

	static final String MIN_SPRING_VERSION = "4.3.22.RELEASE";

	static {
		performVersionChecks();
	}

	public static String getVersion() {
		Package pkg = SpringSecurityCoreVersion.class.getPackage();
		return (pkg != null ? pkg.getImplementationVersion() : null);
	}

	/**
	 * Performs version checks
	 */
	private static void performVersionChecks() {
		performVersionChecks(MIN_SPRING_VERSION);
	}

	/**
	 * Perform version checks with specific min Spring Version
	 *
	 * @param minSpringVersion
	 */
	private static void performVersionChecks(String minSpringVersion) {
		// Check Spring Compatibility
		String springVersion = SpringVersion.getVersion();
		String version = getVersion();

		if (disableChecks(springVersion, version)) {
			return;
		}

		logger.info("You are running with Spring Security Core " + version);
		if (new ComparableVersion(springVersion)
				.compareTo(new ComparableVersion(minSpringVersion)) < 0) {
			logger.warn("**** You are advised to use Spring " + minSpringVersion
					+ " or later with this version. You are running: " + springVersion);
		}
	}

	/**
	 * Disable if springVersion and springSecurityVersion are the same to allow working
	 * with Uber Jars.
	 *
	 * @param springVersion
	 * @param springSecurityVersion
	 * @return
	 */
	private static boolean disableChecks(String springVersion,
			String springSecurityVersion) {
		if (springVersion == null || springVersion.equals(springSecurityVersion)) {
			return true;
		}
		return Boolean.getBoolean(DISABLE_CHECKS);
	}
}
