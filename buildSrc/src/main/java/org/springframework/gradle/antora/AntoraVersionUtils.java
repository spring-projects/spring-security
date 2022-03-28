/*
 * Copyright 2019-2022 the original author or authors.
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

package org.springframework.gradle.antora;

public class AntoraVersionUtils {

	public static String getDefaultAntoraVersion(String projectVersion) {
		int preReleaseIndex = getSnapshotIndex(projectVersion);
		return isSnapshot(projectVersion) ? projectVersion.substring(0, preReleaseIndex) : projectVersion;
	}

	public static String getDefaultAntoraPrerelease(String projectVersion) {
		if (isSnapshot(projectVersion)) {
			int preReleaseIndex = getSnapshotIndex(projectVersion);
			return projectVersion.substring(preReleaseIndex);
		}
		if (isPreRelease(projectVersion)) {
			return Boolean.TRUE.toString();
		}
		return null;
	}

	public static String getDefaultAntoraDisplayVersion(String projectVersion) {
		if (!isSnapshot(projectVersion) && isPreRelease(projectVersion)) {
			return getDefaultAntoraVersion(projectVersion);
		}
		return null;
	}

	private static boolean isSnapshot(String projectVersion) {
		return getSnapshotIndex(projectVersion) >= 0;
	}

	private static int getSnapshotIndex(String projectVersion) {
		return projectVersion.lastIndexOf("-SNAPSHOT");
	}

	private static boolean isPreRelease(String projectVersion) {
		return projectVersion.lastIndexOf("-") >= 0;
	}
}
