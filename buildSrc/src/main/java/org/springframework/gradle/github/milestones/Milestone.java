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

package org.springframework.gradle.github.milestones;

import com.google.gson.annotations.SerializedName;

import java.time.LocalDateTime;
import java.util.Date;

/**
 * @author Steve Riesenberg
 */
public class Milestone {
	private String title;

	private Long number;

	@SerializedName("due_on")
	private LocalDateTime dueOn;

	public String getTitle() {
		return title;
	}

	public void setTitle(String title) {
		this.title = title;
	}

	public Long getNumber() {
		return number;
	}

	public void setNumber(Long number) {
		this.number = number;
	}

	public LocalDateTime getDueOn() {
		return dueOn;
	}

	public void setDueOn(LocalDateTime dueOn) {
		this.dueOn = dueOn;
	}

	@Override
	public String toString() {
		return "Milestone{" +
				"title='" + title + '\'' +
				", number='" + number + '\'' +
				", dueOn='" + dueOn + '\'' +
				'}';
	}
}
