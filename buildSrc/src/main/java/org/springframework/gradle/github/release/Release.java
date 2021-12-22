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

package org.springframework.gradle.github.release;

import com.google.gson.annotations.SerializedName;

/**
 * @author Steve Riesenberg
 */
public class Release {
	@SerializedName("tag_name")
	private final String tag;

	@SerializedName("target_commitish")
	private final String commit;

	@SerializedName("name")
	private final String name;

	@SerializedName("body")
	private final String body;

	@SerializedName("draft")
	private final boolean draft;

	@SerializedName("prerelease")
	private final boolean preRelease;

	@SerializedName("generate_release_notes")
	private final boolean generateReleaseNotes;

	private Release(String tag, String commit, String name, String body, boolean draft, boolean preRelease, boolean generateReleaseNotes) {
		this.tag = tag;
		this.commit = commit;
		this.name = name;
		this.body = body;
		this.draft = draft;
		this.preRelease = preRelease;
		this.generateReleaseNotes = generateReleaseNotes;
	}

	public String getTag() {
		return tag;
	}

	public String getCommit() {
		return commit;
	}

	public String getName() {
		return name;
	}

	public String getBody() {
		return body;
	}

	public boolean isDraft() {
		return draft;
	}

	public boolean isPreRelease() {
		return preRelease;
	}

	public boolean isGenerateReleaseNotes() {
		return generateReleaseNotes;
	}

	@Override
	public String toString() {
		return "Release{" +
				"tag='" + tag + '\'' +
				", commit='" + commit + '\'' +
				", name='" + name + '\'' +
				", body='" + body + '\'' +
				", draft=" + draft +
				", preRelease=" + preRelease +
				", generateReleaseNotes=" + generateReleaseNotes +
				'}';
	}

	public static Builder tag(String tag) {
		return new Builder().tag(tag);
	}

	public static Builder commit(String commit) {
		return new Builder().commit(commit);
	}

	public static final class Builder {
		private String tag;
		private String commit;
		private String name;
		private String body;
		private boolean draft;
		private boolean preRelease;
		private boolean generateReleaseNotes;

		private Builder() {
		}

		public Builder tag(String tag) {
			this.tag = tag;
			return this;
		}

		public Builder commit(String commit) {
			this.commit = commit;
			return this;
		}

		public Builder name(String name) {
			this.name = name;
			return this;
		}

		public Builder body(String body) {
			this.body = body;
			return this;
		}

		public Builder draft(boolean draft) {
			this.draft = draft;
			return this;
		}

		public Builder preRelease(boolean preRelease) {
			this.preRelease = preRelease;
			return this;
		}

		public Builder generateReleaseNotes(boolean generateReleaseNotes) {
			this.generateReleaseNotes = generateReleaseNotes;
			return this;
		}

		public Release build() {
			return new Release(tag, commit, name, body, draft, preRelease, generateReleaseNotes);
		}
	}
}
