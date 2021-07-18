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

package org.springframework.security.access;

import java.util.Locale;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.context.i18n.LocaleContextHolder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Dayan Kodippily
 * @since 5.6
 */
@ExtendWith(MockitoExtension.class)
public class AccessDeniedExceptionTests {

	@Mock
	private Locale beforeSystem;

	@Mock
	private Locale beforeHolder;

	@BeforeEach
	public void setup() {
		this.beforeSystem = Locale.getDefault();
		this.beforeHolder = LocaleContextHolder.getLocale();
	}

	@AfterEach
	public void cleanup() {
		Locale.setDefault(this.beforeSystem);
		LocaleContextHolder.setLocale(this.beforeHolder);
	}

	@Test
	public void getLocalizedMessageWhenDefaultLocaleUnitedStatesThenReturnsMessageInEnglish() {
		Locale.setDefault(Locale.US);
		LocaleContextHolder.setLocale(Locale.US);

		AccessDeniedException accessDeniedException = new AccessDeniedException("AccessDeniedException.accessDenied");
		String englishLocalizedExceptionMessage = accessDeniedException.getLocalizedMessage();

		assertThat(englishLocalizedExceptionMessage).isEqualTo("Access is denied");
	}

	@Test
	public void getLocalizedMessageWhenDefaultLocaleFranceThenReturnsMessageInFrench() {
		Locale.setDefault(Locale.FRANCE);
		LocaleContextHolder.setLocale(Locale.FRANCE);

		AccessDeniedException accessDeniedException = new AccessDeniedException("AccessDeniedException.accessDenied");
		String frenchLocalizedExceptionMessage = accessDeniedException.getLocalizedMessage();

		assertThat(frenchLocalizedExceptionMessage).isEqualTo("Acc\u00E8s refus\u00E9");
	}

	@Test
	public void getLocalizedMessageWhenDefaultLocaleGermanNotFoundThenReturnsMessageInEnglish() {
		Locale.setDefault(Locale.GERMANY);
		LocaleContextHolder.setLocale(Locale.GERMANY);

		AccessDeniedException accessDeniedException = new AccessDeniedException("AccessDeniedException.accessDenied");
		String frenchLocalizedExceptionMessage = accessDeniedException.getLocalizedMessage();

		assertThat(frenchLocalizedExceptionMessage).isEqualTo("Access is denied");
	}

	@Test
	public void getLocalizedMessageWhenMessageIsNotLocalizedKeyThenReturnsOriginalMessage() {
		AccessDeniedException accessDeniedException = new AccessDeniedException("Yet another Exception");
		String defaultMessage = accessDeniedException.getLocalizedMessage();

		assertThat(defaultMessage).isEqualTo("Yet another Exception");
	}

}
