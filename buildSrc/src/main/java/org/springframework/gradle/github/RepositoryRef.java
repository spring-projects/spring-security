package org.springframework.gradle.github;

import java.io.Serializable;

public class RepositoryRef implements Serializable {

	private static final long serialVersionUID = 7151218536746822797L;

	private String owner;

	private String name;

	public RepositoryRef() {
	}

	public RepositoryRef(String owner, String name) {
		this.owner = owner;
		this.name = name;
	}

	public String getOwner() {
		return owner;
	}

	public void setOwner(String owner) {
		this.owner = owner;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@Override
	public String toString() {
		return "RepositoryRef{" +
				"owner='" + owner + '\'' +
				", name='" + name + '\'' +
				'}';
	}

	public static RepositoryRefBuilder owner(String owner) {
		return new RepositoryRefBuilder().owner(owner);
	}

	public static final class RepositoryRefBuilder {
		private String owner;
		private String repository;

		private RepositoryRefBuilder() {
		}

		private RepositoryRefBuilder owner(String owner) {
			this.owner = owner;
			return this;
		}

		public RepositoryRefBuilder repository(String repository) {
			this.repository = repository;
			return this;
		}

		public RepositoryRef build() {
			return new RepositoryRef(owner, repository);
		}
	}
}
