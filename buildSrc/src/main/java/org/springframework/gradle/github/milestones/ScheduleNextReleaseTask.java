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

package org.springframework.gradle.github.milestones;

import java.time.LocalDate;
import java.time.LocalTime;

import org.gradle.api.Action;
import org.gradle.api.DefaultTask;
import org.gradle.api.tasks.Input;
import org.gradle.api.tasks.TaskAction;

import org.springframework.gradle.github.RepositoryRef;

/**
 * @author Steve Riesenberg
 */
public class ScheduleNextReleaseTask extends DefaultTask {
	@Input
	private RepositoryRef repository = new RepositoryRef();

	@Input
	private String gitHubAccessToken;

	@Input
	private String version;

	@Input
	private Integer weekOfMonth;

	@Input
	private Integer dayOfWeek;

	@TaskAction
	public void scheduleNextRelease() {
		GitHubMilestoneApi gitHubMilestoneApi = new GitHubMilestoneApi(this.gitHubAccessToken);
		String nextReleaseMilestone = gitHubMilestoneApi.getNextReleaseMilestone(this.repository, this.version);

		// If the next release contains a dash (e.g. 5.6.0-RC1), it is already scheduled
		if (nextReleaseMilestone.contains("-")) {
			return;
		}

		// Check to see if a scheduled GA version already exists
		boolean hasExistingMilestone = gitHubMilestoneApi.getMilestones(this.repository).stream()
				.anyMatch(milestone -> nextReleaseMilestone.equals(milestone.getTitle()));
		if (hasExistingMilestone) {
			return;
		}

		// Next milestone is either a patch version or minor version
		// Note: Major versions will be handled like minor and get a release
		// train which can be manually updated to match the desired schedule.
		if (nextReleaseMilestone.endsWith(".0")) {
			// Create M1, M2, M3, RC1 and GA milestones for release train
			getReleaseTrain(nextReleaseMilestone).getTrainDates().forEach((milestoneTitle, dueOn) -> {
				Milestone milestone = new Milestone();
				milestone.setTitle(milestoneTitle);
				// Note: GitHub seems to store full date/time as UTC then displays
				// as a date (no time) in your timezone, which means the date will
				// not always be the same date as we intend.
				// Using 12pm/noon UTC allows GitHub to schedule and display the
				// correct date.
				milestone.setDueOn(dueOn.atTime(LocalTime.NOON));
				gitHubMilestoneApi.createMilestone(this.repository, milestone);
			});
		} else {
			// Create GA milestone for patch release on the next even month
			LocalDate startDate = LocalDate.now();
			LocalDate dueOn = getReleaseTrain(nextReleaseMilestone).getNextReleaseDate(startDate);
			Milestone milestone = new Milestone();
			milestone.setTitle(nextReleaseMilestone);
			milestone.setDueOn(dueOn.atTime(LocalTime.NOON));
			gitHubMilestoneApi.createMilestone(this.repository, milestone);
		}
	}

	private SpringReleaseTrain getReleaseTrain(String nextReleaseMilestone) {
		SpringReleaseTrainSpec releaseTrainSpec =
				SpringReleaseTrainSpec.builder()
						.nextTrain()
						.version(nextReleaseMilestone)
						.weekOfMonth(this.weekOfMonth)
						.dayOfWeek(this.dayOfWeek)
						.build();

		return new SpringReleaseTrain(releaseTrainSpec);
	}

	public RepositoryRef getRepository() {
		return this.repository;
	}

	public void repository(Action<RepositoryRef> repository) {
		repository.execute(this.repository);
	}

	public void setRepository(RepositoryRef repository) {
		this.repository = repository;
	}

	public String getGitHubAccessToken() {
		return this.gitHubAccessToken;
	}

	public void setGitHubAccessToken(String gitHubAccessToken) {
		this.gitHubAccessToken = gitHubAccessToken;
	}

	public String getVersion() {
		return this.version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	public Integer getWeekOfMonth() {
		return weekOfMonth;
	}

	public void setWeekOfMonth(Integer weekOfMonth) {
		this.weekOfMonth = weekOfMonth;
	}

	public Integer getDayOfWeek() {
		return dayOfWeek;
	}

	public void setDayOfWeek(Integer dayOfWeek) {
		this.dayOfWeek = dayOfWeek;
	}
}
