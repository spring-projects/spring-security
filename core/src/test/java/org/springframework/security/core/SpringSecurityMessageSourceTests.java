/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.core;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Locale;

import org.junit.Test;
import org.springframework.context.i18n.LocaleContextHolder;
import org.springframework.context.support.MessageSourceAccessor;

/**
 * Tests {@link org.springframework.security.core.SpringSecurityMessageSource}.
 */
public class SpringSecurityMessageSourceTests {

	// ~ Methods
	// ========================================================================================================
	@Test
	public void testOperation() {
		SpringSecurityMessageSource msgs = new SpringSecurityMessageSource();
		assertThat("\u4E0D\u5141\u8BB8\u8BBF\u95EE").isEqualTo(
				msgs.getMessage("AbstractAccessDecisionManager.accessDenied", null, Locale.SIMPLIFIED_CHINESE));
	}

	@Test
	public void testReplacableLookup() {
		// Change Locale to English
		Locale before = LocaleContextHolder.getLocale();
		LocaleContextHolder.setLocale(Locale.FRENCH);

		// Cause a message to be generated
		MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
		assertThat("Le jeton nonce est compromis FOOBAR").isEqualTo(messages.getMessage(
				"DigestAuthenticationFilter.nonceCompromised", new Object[] { "FOOBAR" }, "ERROR - FAILED TO LOOKUP"));

		// Revert to original Locale
		LocaleContextHolder.setLocale(before);
	}

	// SEC-3013
	@Test
	public void germanSystemLocaleWithEnglishLocaleContextHolder() {
		Locale beforeSystem = Locale.getDefault();
		Locale.setDefault(Locale.GERMAN);

		Locale beforeHolder = LocaleContextHolder.getLocale();
		LocaleContextHolder.setLocale(Locale.US);

		MessageSourceAccessor msgs = SpringSecurityMessageSource.getAccessor();
		assertThat("Access is denied")
				.isEqualTo(msgs.getMessage("AbstractAccessDecisionManager.accessDenied", "Ooops"));

		// Revert to original Locale
		Locale.setDefault(beforeSystem);
		LocaleContextHolder.setLocale(beforeHolder);
	}

}
