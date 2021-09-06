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

package org.springframework.security.core;

import java.util.Locale;

import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceResolvable;
import org.springframework.context.NoSuchMessageException;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.lang.Nullable;

/**
 * Like {@link MessageSourceAccessor}, this is a helper class for easy access to message
 * from a MessageSource, providing various overloaded getMessage methods.
 *
 * <p>
 * Unlike MessageSourceAccessor, it sets the SpringSecurityMessageSource to fallback
 * messageSource. When a user provides messageSource cannot find information, will make
 * SpringSecurityMessageSource out looking.
 *
 * @author Hccake
 * @since 5.6.0
 * @see MessageSourceAccessor
 */
public class SpringSecurityMessageSourceAccessor extends MessageSourceAccessor {

	private final MessageSource messageSource;

	/**
	 * Create a new MessageSourceAccessor, using LocaleContextHolder's locale as default
	 * locale, and always use SpringSecurityMessageSource to get the message
	 * @see org.springframework.context.i18n.LocaleContextHolder#getLocale()
	 */
	public SpringSecurityMessageSourceAccessor() {
		super(new SpringSecurityMessageSource());
		this.messageSource = null;
	}

	/**
	 * Create a new MessageSourceAccessor, using LocaleContextHolder's locale as default
	 * locale.
	 * @param messageSource the MessageSource to wrap
	 * @see org.springframework.context.i18n.LocaleContextHolder#getLocale()
	 */
	public SpringSecurityMessageSourceAccessor(MessageSource messageSource) {
		super(new SpringSecurityMessageSource());
		this.messageSource = messageSource;
	}

	/**
	 * Create a new MessageSourceAccessor, using the given default locale.
	 * @param messageSource the MessageSource to wrap
	 * @param defaultLocale the default locale to use for message access
	 */
	public SpringSecurityMessageSourceAccessor(MessageSource messageSource, Locale defaultLocale) {
		super(new SpringSecurityMessageSource(), defaultLocale);
		this.messageSource = messageSource;
	}

	/**
	 * Retrieve the message for the given code and the default Locale.
	 * @param code the code of the message
	 * @param defaultMessage the String to return if the lookup fails
	 * @return the message
	 */
	@Override
	public String getMessage(String code, String defaultMessage) {
		return this.getMessage(code, defaultMessage, getDefaultLocale());
	}

	/**
	 * Retrieve the message for the given code and the given Locale.
	 * @param code the code of the message
	 * @param defaultMessage the String to return if the lookup fails
	 * @param locale the Locale in which to do lookup
	 * @return the message
	 */
	@Override
	public String getMessage(String code, String defaultMessage, Locale locale) {
		return this.getMessage(code, null, defaultMessage, locale);
	}

	/**
	 * Retrieve the message for the given code and the default Locale.
	 * @param code the code of the message
	 * @param args arguments for the message, or {@code null} if none
	 * @param defaultMessage the String to return if the lookup fails
	 * @return the message
	 */
	@Override
	public String getMessage(String code, @Nullable Object[] args, String defaultMessage) {
		return this.getMessage(code, args, defaultMessage, getDefaultLocale());
	}

	/**
	 * Retrieve the message for the given code and the given Locale.
	 * @param code the code of the message
	 * @param args arguments for the message, or {@code null} if none
	 * @param defaultMessage the String to return if the lookup fails
	 * @param locale the Locale in which to do lookup
	 * @return the message
	 */
	@Override
	public String getMessage(String code, @Nullable Object[] args, String defaultMessage, Locale locale) {
		String msg;
		if (this.messageSource != null) {
			try {
				msg = this.messageSource.getMessage(code, args, locale);
			}
			catch (NoSuchMessageException ex) {
				msg = super.getMessage(code, args, defaultMessage, locale);
			}
		}
		else {
			msg = super.getMessage(code, args, defaultMessage, locale);
		}
		return msg;
	}

	/**
	 * Retrieve the message for the given code and the default Locale.
	 * @param code the code of the message
	 * @return the message
	 * @throws org.springframework.context.NoSuchMessageException if not found
	 */
	@Override
	public String getMessage(String code) throws NoSuchMessageException {
		return this.getMessage(code, getDefaultLocale());
	}

	/**
	 * Retrieve the message for the given code and the given Locale.
	 * @param code the code of the message
	 * @param locale the Locale in which to do lookup
	 * @return the message
	 * @throws org.springframework.context.NoSuchMessageException if not found
	 */
	@Override
	public String getMessage(String code, Locale locale) throws NoSuchMessageException {
		return this.getMessage(code, new Object[] {}, locale);
	}

	/**
	 * Retrieve the message for the given code and the default Locale.
	 * @param code the code of the message
	 * @param args arguments for the message, or {@code null} if none
	 * @return the message
	 * @throws org.springframework.context.NoSuchMessageException if not found
	 */
	@Override
	public String getMessage(String code, @Nullable Object[] args) throws NoSuchMessageException {
		return this.getMessage(code, args, getDefaultLocale());
	}

	/**
	 * Retrieve the message for the given code and the given Locale.
	 * @param code the code of the message
	 * @param args arguments for the message, or {@code null} if none
	 * @param locale the Locale in which to do lookup
	 * @return the message
	 * @throws org.springframework.context.NoSuchMessageException if not found
	 */
	@Override
	public String getMessage(String code, @Nullable Object[] args, Locale locale) throws NoSuchMessageException {
		String msg;
		if (this.messageSource != null) {
			try {
				msg = this.messageSource.getMessage(code, args, locale);
			}
			catch (NoSuchMessageException ex) {
				msg = super.getMessage(code, args, locale);
			}
		}
		else {
			msg = super.getMessage(code, args, locale);
		}
		return msg;
	}

	/**
	 * Retrieve the given MessageSourceResolvable (e.g. an ObjectError instance) in the
	 * default Locale.
	 * @param resolvable the MessageSourceResolvable
	 * @return the message
	 * @throws org.springframework.context.NoSuchMessageException if not found
	 */
	@Override
	public String getMessage(MessageSourceResolvable resolvable) throws NoSuchMessageException {
		return this.getMessage(resolvable, getDefaultLocale());
	}

	/**
	 * Retrieve the given MessageSourceResolvable (e.g. an ObjectError instance) in the
	 * given Locale.
	 * @param resolvable the MessageSourceResolvable
	 * @param locale the Locale in which to do lookup
	 * @return the message
	 * @throws org.springframework.context.NoSuchMessageException if not found
	 */
	@Override
	public String getMessage(MessageSourceResolvable resolvable, Locale locale) throws NoSuchMessageException {
		String msg;
		if (this.messageSource != null) {
			try {
				msg = this.messageSource.getMessage(resolvable, locale);
			}
			catch (NoSuchMessageException ex) {
				msg = super.getMessage(resolvable, locale);
			}
		}
		else {
			msg = super.getMessage(resolvable, locale);
		}
		return msg;
	}

}
