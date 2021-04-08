package org.springframework.gradle.github.milestones;

public class Milestone {
	private String title;

	private long number;

	public String getTitle() {
		return title;
	}

	public void setTitle(String title) {
		this.title = title;
	}

	public long getNumber() {
		return number;
	}

	public void setNumber(long number) {
		this.number = number;
	}

	@Override
	public String toString() {
		return "Milestone{" +
				"title='" + title + '\'' +
				", number=" + number +
				'}';
	}
}
