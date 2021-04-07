/*
 * Copyright 2019-2020 the original author or authors.
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

package org.springframework.gradle.sagan;

import java.util.regex.Pattern;

/**
 * Domain object for creating a new release version.
 */
public class Release {
	private String version;

	private ReleaseStatus status;

	private boolean current;

	private String referenceDocUrl;

	private String apiDocUrl;

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	public ReleaseStatus getStatus() {
		return status;
	}

	public void setStatus(ReleaseStatus status) {
		this.status = status;
	}

	public boolean isCurrent() {
		return current;
	}

	public void setCurrent(boolean current) {
		this.current = current;
	}

	public String getReferenceDocUrl() {
		return referenceDocUrl;
	}

	public void setReferenceDocUrl(String referenceDocUrl) {
		this.referenceDocUrl = referenceDocUrl;
	}

	public String getApiDocUrl() {
		return apiDocUrl;
	}

	public void setApiDocUrl(String apiDocUrl) {
		this.apiDocUrl = apiDocUrl;
	}

	@Override
	public String toString() {
		return "Release{" +
				"version='" + version + '\'' +
				", status=" + status +
				", current=" + current +
				", referenceDocUrl='" + referenceDocUrl + '\'' +
				", apiDocUrl='" + apiDocUrl + '\'' +
				'}';
	}

	public enum ReleaseStatus {
		/**
		 * Unstable version with limited support
		 */
		SNAPSHOT,
		/**
		 * Pre-Release version meant to be tested by the community
		 */
		PRERELEASE,
		/**
		 * Release Generally Available on public artifact repositories and enjoying full support from maintainers
		 */
		GENERAL_AVAILABILITY;

		private static final Pattern PRERELEASE_PATTERN = Pattern.compile("[A-Za-z0-9\\.\\-]+?(M|RC)\\d+");

		private static final String SNAPSHOT_SUFFIX = "SNAPSHOT";

		/**
		 * Parse the ReleaseStatus from a String
		 * @param version a project version
		 * @return the release status for this version
		 */
		public static ReleaseStatus parse(String version) {
			if (version == null) {
				throw new IllegalArgumentException("version cannot be null");
			}
			if (version.endsWith(SNAPSHOT_SUFFIX)) {
				return SNAPSHOT;
			}
			if (PRERELEASE_PATTERN.matcher(version).matches()) {
				return PRERELEASE;
			}
			return GENERAL_AVAILABILITY;
		}
	}

}
