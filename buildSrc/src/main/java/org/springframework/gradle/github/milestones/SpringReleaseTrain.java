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

import java.time.DayOfWeek;
import java.time.LocalDate;
import java.time.Month;
import java.time.Year;
import java.time.temporal.TemporalAdjuster;
import java.time.temporal.TemporalAdjusters;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Spring release train generator based on rules contained in a specification.
 * <p>
 * The rules are:
 * <ol>
 *     <li>Train 1 (January-May) or 2 (July-November)</li>
 *     <li>Version number (e.g. 0.1.2, 1.0.0, etc.)</li>
 *     <li>Week of month (1st, 2nd, 3rd, 4th)</li>
 *     <li>Day of week (Monday-Friday)</li>
 *     <li>Year (e.g. 2020, 2021, etc.)</li>
 * </ol>
 *
 * The release train generated will contain M1, M2, M3, RC1 and GA versions
 * mapped to their respective dates in the train.
 *
 * @author Steve Riesenberg
 */
public final class SpringReleaseTrain {
	private final SpringReleaseTrainSpec releaseTrainSpec;

	public SpringReleaseTrain(SpringReleaseTrainSpec releaseTrainSpec) {
		this.releaseTrainSpec = releaseTrainSpec;
	}

	/**
	 * Calculate release train dates based on the release train specification.
	 *
	 * @return A mapping of release milestones to scheduled release dates
	 */
	public Map<String, LocalDate> getTrainDates() {
		Map<String, LocalDate> releaseDates = new LinkedHashMap<>();
		switch (this.releaseTrainSpec.getTrain()) {
			case ONE:
				addTrainDate(releaseDates, "M1", Month.JANUARY);
				addTrainDate(releaseDates, "M2", Month.FEBRUARY);
				addTrainDate(releaseDates, "M3", Month.MARCH);
				addTrainDate(releaseDates, "RC1", Month.APRIL);
				addTrainDate(releaseDates, null, Month.MAY);
				break;
			case TWO:
				addTrainDate(releaseDates, "M1", Month.JULY);
				addTrainDate(releaseDates, "M2", Month.AUGUST);
				addTrainDate(releaseDates, "M3", Month.SEPTEMBER);
				addTrainDate(releaseDates, "RC1", Month.OCTOBER);
				addTrainDate(releaseDates, null, Month.NOVEMBER);
				break;
		}

		return releaseDates;
	}

	/**
	 * Determine if a given date matches the due date of given version.
	 *
	 * @param version The version number (e.g. 5.6.0-M1, 5.6.0, etc.)
	 * @param expectedDate The expected date
	 * @return true if the given date matches the due date of the given version, false otherwise
	 */
	public boolean isTrainDate(String version, LocalDate expectedDate) {
		return expectedDate.isEqual(getTrainDates().get(version));
	}

	/**
	 * Calculate the next release date following the given date.
	 * <p>
	 * The next release date is always on an even month so that a patch release
	 * is the month after the GA version of a release train. This method does
	 * not consider the year of the release train, only the given start date.
	 *
	 * @param startDate The start date
	 * @return The next release date following the given date
	 */
	public LocalDate getNextReleaseDate(LocalDate startDate) {
		LocalDate trainDate;
		LocalDate currentDate = startDate;
		do {
			trainDate = calculateReleaseDate(
					Year.of(currentDate.getYear()),
					currentDate.getMonth(),
					this.releaseTrainSpec.getDayOfWeek().getDayOfWeek(),
					this.releaseTrainSpec.getWeekOfMonth().getDayOffset()
			);
			currentDate = currentDate.plusMonths(1);
		} while (!trainDate.isAfter(startDate) || trainDate.getMonthValue() % 2 != 0);

		return trainDate;
	}

	private void addTrainDate(Map<String, LocalDate> releaseDates, String milestone, Month month) {
		LocalDate releaseDate = calculateReleaseDate(
				this.releaseTrainSpec.getYear(),
				month,
				this.releaseTrainSpec.getDayOfWeek().getDayOfWeek(),
				this.releaseTrainSpec.getWeekOfMonth().getDayOffset()
		);
		String suffix = (milestone == null) ? "" : "-" + milestone;
		releaseDates.put(this.releaseTrainSpec.getVersion() + suffix, releaseDate);
	}

	private static LocalDate calculateReleaseDate(Year year, Month month, DayOfWeek dayOfWeek, int dayOffset) {
		TemporalAdjuster nextMonday = TemporalAdjusters.nextOrSame(DayOfWeek.MONDAY);
		TemporalAdjuster nextDayOfWeek = TemporalAdjusters.nextOrSame(dayOfWeek);

		LocalDate firstDayOfMonth = year.atMonth(month).atDay(1);
		LocalDate firstMondayOfMonth = firstDayOfMonth.with(nextMonday);

		return firstMondayOfMonth.with(nextDayOfWeek).plusDays(dayOffset);
	}
}
