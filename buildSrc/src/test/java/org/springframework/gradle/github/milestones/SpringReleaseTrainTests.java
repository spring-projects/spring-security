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
import java.time.Year;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import org.springframework.gradle.github.milestones.SpringReleaseTrainSpec.Train;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Steve Riesenberg
 */
public class SpringReleaseTrainTests {
	@ParameterizedTest
	@CsvSource({
			"2019-12-31, ONE, 2020",
			"2020-01-01, ONE, 2020",
			"2020-01-31, ONE, 2020",
			"2020-02-01, TWO, 2020",
			"2020-07-31, TWO, 2020",
			"2020-08-01, ONE, 2021"
	})
	public void nextTrainWhenBoundaryConditionsThenSuccess(LocalDate startDate, Train expectedTrain, Year expectedYear) {
		SpringReleaseTrainSpec releaseTrainSpec =
				SpringReleaseTrainSpec.builder()
						.nextTrain(startDate)
						.version("1.0.0")
						.weekOfMonth(2)
						.dayOfWeek(2)
						.build();
		assertThat(releaseTrainSpec.getTrain()).isEqualTo(expectedTrain);
		assertThat(releaseTrainSpec.getYear()).isEqualTo(expectedYear);
	}

	@Test
	public void getTrainDatesWhenTrainOneIsSecondTuesdayOf2020ThenSuccess() {
		SpringReleaseTrainSpec releaseTrainSpec =
				SpringReleaseTrainSpec.builder()
						.train(1)
						.version("1.0.0")
						.weekOfMonth(2)
						.dayOfWeek(2)
						.year(2020)
						.build();

		SpringReleaseTrain releaseTrain = new SpringReleaseTrain(releaseTrainSpec);
		Map<String, LocalDate> trainDates = releaseTrain.getTrainDates();
		assertThat(trainDates).hasSize(5);
		assertThat(trainDates.get("1.0.0-M1")).isEqualTo(LocalDate.of(2020, 1, 14));
		assertThat(trainDates.get("1.0.0-M2")).isEqualTo(LocalDate.of(2020, 2, 11));
		assertThat(trainDates.get("1.0.0-M3")).isEqualTo(LocalDate.of(2020, 3, 10));
		assertThat(trainDates.get("1.0.0-RC1")).isEqualTo(LocalDate.of(2020, 4, 14));
		assertThat(trainDates.get("1.0.0")).isEqualTo(LocalDate.of(2020, 5, 12));
	}

	@Test
	public void getTrainDatesWhenTrainTwoIsSecondTuesdayOf2020ThenSuccess() {
		SpringReleaseTrainSpec releaseTrainSpec =
				SpringReleaseTrainSpec.builder()
						.train(2)
						.version("1.0.0")
						.weekOfMonth(2)
						.dayOfWeek(2)
						.year(2020)
						.build();

		SpringReleaseTrain releaseTrain = new SpringReleaseTrain(releaseTrainSpec);
		Map<String, LocalDate> trainDates = releaseTrain.getTrainDates();
		assertThat(trainDates).hasSize(5);
		assertThat(trainDates.get("1.0.0-M1")).isEqualTo(LocalDate.of(2020, 7, 14));
		assertThat(trainDates.get("1.0.0-M2")).isEqualTo(LocalDate.of(2020, 8, 11));
		assertThat(trainDates.get("1.0.0-M3")).isEqualTo(LocalDate.of(2020, 9, 15));
		assertThat(trainDates.get("1.0.0-RC1")).isEqualTo(LocalDate.of(2020, 10, 13));
		assertThat(trainDates.get("1.0.0")).isEqualTo(LocalDate.of(2020, 11, 10));
	}

	@Test
	public void getTrainDatesWhenTrainOneIsSecondTuesdayOf2022ThenSuccess() {
		SpringReleaseTrainSpec releaseTrainSpec =
				SpringReleaseTrainSpec.builder()
						.train(1)
						.version("1.0.0")
						.weekOfMonth(2)
						.dayOfWeek(2)
						.year(2022)
						.build();

		SpringReleaseTrain releaseTrain = new SpringReleaseTrain(releaseTrainSpec);
		Map<String, LocalDate> trainDates = releaseTrain.getTrainDates();
		assertThat(trainDates).hasSize(5);
		assertThat(trainDates.get("1.0.0-M1")).isEqualTo(LocalDate.of(2022, 1, 11));
		assertThat(trainDates.get("1.0.0-M2")).isEqualTo(LocalDate.of(2022, 2, 15));
		assertThat(trainDates.get("1.0.0-M3")).isEqualTo(LocalDate.of(2022, 3, 15));
		assertThat(trainDates.get("1.0.0-RC1")).isEqualTo(LocalDate.of(2022, 4, 12));
		assertThat(trainDates.get("1.0.0")).isEqualTo(LocalDate.of(2022, 5, 10));
	}

	@Test
	public void getTrainDatesWhenTrainTwoIsSecondTuesdayOf2022ThenSuccess() {
		SpringReleaseTrainSpec releaseTrainSpec =
				SpringReleaseTrainSpec.builder()
						.train(2)
						.version("1.0.0")
						.weekOfMonth(2)
						.dayOfWeek(2)
						.year(2022)
						.build();

		SpringReleaseTrain releaseTrain = new SpringReleaseTrain(releaseTrainSpec);
		Map<String, LocalDate> trainDates = releaseTrain.getTrainDates();
		assertThat(trainDates).hasSize(5);
		assertThat(trainDates.get("1.0.0-M1")).isEqualTo(LocalDate.of(2022, 7, 12));
		assertThat(trainDates.get("1.0.0-M2")).isEqualTo(LocalDate.of(2022, 8, 9));
		assertThat(trainDates.get("1.0.0-M3")).isEqualTo(LocalDate.of(2022, 9, 13));
		assertThat(trainDates.get("1.0.0-RC1")).isEqualTo(LocalDate.of(2022, 10, 11));
		assertThat(trainDates.get("1.0.0")).isEqualTo(LocalDate.of(2022, 11, 15));
	}

	@Test
	public void getTrainDatesWhenTrainOneIsThirdMondayOf2022ThenSuccess() {
		SpringReleaseTrainSpec releaseTrainSpec =
				SpringReleaseTrainSpec.builder()
						.train(1)
						.version("1.0.0")
						.weekOfMonth(3)
						.dayOfWeek(1)
						.year(2022)
						.build();

		SpringReleaseTrain releaseTrain = new SpringReleaseTrain(releaseTrainSpec);
		Map<String, LocalDate> trainDates = releaseTrain.getTrainDates();
		assertThat(trainDates).hasSize(5);
		assertThat(trainDates.get("1.0.0-M1")).isEqualTo(LocalDate.of(2022, 1, 17));
		assertThat(trainDates.get("1.0.0-M2")).isEqualTo(LocalDate.of(2022, 2, 21));
		assertThat(trainDates.get("1.0.0-M3")).isEqualTo(LocalDate.of(2022, 3, 21));
		assertThat(trainDates.get("1.0.0-RC1")).isEqualTo(LocalDate.of(2022, 4, 18));
		assertThat(trainDates.get("1.0.0")).isEqualTo(LocalDate.of(2022, 5, 16));
	}

	@Test
	public void getTrainDatesWhenTrainTwoIsThirdMondayOf2022ThenSuccess() {
		SpringReleaseTrainSpec releaseTrainSpec =
				SpringReleaseTrainSpec.builder()
						.train(2)
						.version("1.0.0")
						.weekOfMonth(3)
						.dayOfWeek(1)
						.year(2022)
						.build();

		SpringReleaseTrain releaseTrain = new SpringReleaseTrain(releaseTrainSpec);
		Map<String, LocalDate> trainDates = releaseTrain.getTrainDates();
		assertThat(trainDates).hasSize(5);
		assertThat(trainDates.get("1.0.0-M1")).isEqualTo(LocalDate.of(2022, 7, 18));
		assertThat(trainDates.get("1.0.0-M2")).isEqualTo(LocalDate.of(2022, 8, 15));
		assertThat(trainDates.get("1.0.0-M3")).isEqualTo(LocalDate.of(2022, 9, 19));
		assertThat(trainDates.get("1.0.0-RC1")).isEqualTo(LocalDate.of(2022, 10, 17));
		assertThat(trainDates.get("1.0.0")).isEqualTo(LocalDate.of(2022, 11, 21));
	}

	@Test
	public void isTrainDateWhenTrainOneIsThirdMondayOf2022ThenSuccess() {
		SpringReleaseTrainSpec releaseTrainSpec =
				SpringReleaseTrainSpec.builder()
						.train(1)
						.version("1.0.0")
						.weekOfMonth(3)
						.dayOfWeek(1)
						.year(2022)
						.build();

		SpringReleaseTrain releaseTrain = new SpringReleaseTrain(releaseTrainSpec);
		for (int dayOfMonth = 1; dayOfMonth <= 31; dayOfMonth++) {
			assertThat(releaseTrain.isTrainDate("1.0.0-M1", LocalDate.of(2022, 1, dayOfMonth))).isEqualTo(dayOfMonth == 17);
		}
		for (int dayOfMonth = 1; dayOfMonth <= 28; dayOfMonth++) {
			assertThat(releaseTrain.isTrainDate("1.0.0-M2", LocalDate.of(2022, 2, dayOfMonth))).isEqualTo(dayOfMonth == 21);
		}
		for (int dayOfMonth = 1; dayOfMonth <= 31; dayOfMonth++) {
			assertThat(releaseTrain.isTrainDate("1.0.0-M3", LocalDate.of(2022, 3, dayOfMonth))).isEqualTo(dayOfMonth == 21);
		}
		for (int dayOfMonth = 1; dayOfMonth <= 30; dayOfMonth++) {
			assertThat(releaseTrain.isTrainDate("1.0.0-RC1", LocalDate.of(2022, 4, dayOfMonth))).isEqualTo(dayOfMonth == 18);
		}
		for (int dayOfMonth = 1; dayOfMonth <= 31; dayOfMonth++) {
			assertThat(releaseTrain.isTrainDate("1.0.0", LocalDate.of(2022, 5, dayOfMonth))).isEqualTo(dayOfMonth == 16);
		}
	}

	@ParameterizedTest
	@CsvSource({
			"2022-01-01, 2022-02-21",
			"2022-02-01, 2022-02-21",
			"2022-02-21, 2022-04-18",
			"2022-03-01, 2022-04-18",
			"2022-04-01, 2022-04-18",
			"2022-04-18, 2022-06-20",
			"2022-05-01, 2022-06-20",
			"2022-06-01, 2022-06-20",
			"2022-06-20, 2022-08-15",
			"2022-07-01, 2022-08-15",
			"2022-08-01, 2022-08-15",
			"2022-08-15, 2022-10-17",
			"2022-09-01, 2022-10-17",
			"2022-10-01, 2022-10-17",
			"2022-10-17, 2022-12-19",
			"2022-11-01, 2022-12-19",
			"2022-12-01, 2022-12-19",
			"2022-12-19, 2023-02-20"
	})
	public void getNextReleaseDateWhenBoundaryConditionsThenSuccess(LocalDate startDate, LocalDate expectedDate) {
		SpringReleaseTrainSpec releaseTrainSpec =
				SpringReleaseTrainSpec.builder()
						.train(1)
						.version("1.0.0")
						.weekOfMonth(3)
						.dayOfWeek(1)
						.year(2022)
						.build();

		SpringReleaseTrain releaseTrain = new SpringReleaseTrain(releaseTrainSpec);
		assertThat(releaseTrain.getNextReleaseDate(startDate)).isEqualTo(expectedDate);
	}
}
