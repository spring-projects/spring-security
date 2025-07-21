/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.web.authentication.preauth.x509;

import java.security.cert.X509Certificate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.util.Assert;

/**
 * Obtains the principal from a certificate using a regular expression match against the
 * Subject (as returned by a call to {@link X509Certificate#getSubjectDN()}).
 * <p>
 * The regular expression should contain a single group; for example the default
 * expression "CN=(.*?)(?:,|$)" matches the common name field. So "CN=Jimi Hendrix,
 * OU=..." will give a user name of "Jimi Hendrix".
 * <p>
 * The matches are case insensitive. So "emailAddress=(.*?)," will match
 * "EMAILADDRESS=jimi@hendrix.org, CN=..." giving a user name "jimi@hendrix.org"
 *
 * @author Luke Taylor
 * @deprecated Please use {@link SubjectX500PrincipalExtractor} instead
 */
@Deprecated
public class SubjectDnX509PrincipalExtractor implements X509PrincipalExtractor, MessageSourceAware {

	protected final Log logger = LogFactory.getLog(getClass());

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	private Pattern subjectDnPattern;

	public SubjectDnX509PrincipalExtractor() {
		setSubjectDnRegex("CN=(.*?)(?:,|$)");
	}

	@Override
	public Object extractPrincipal(X509Certificate clientCert) {
		// String subjectDN = clientCert.getSubjectX500Principal().getName();
		String subjectDN = clientCert.getSubjectDN().getName();
		this.logger.debug(LogMessage.format("Subject DN is '%s'", subjectDN));
		Matcher matcher = this.subjectDnPattern.matcher(subjectDN);
		if (!matcher.find()) {
			throw new BadCredentialsException(this.messages.getMessage("SubjectDnX509PrincipalExtractor.noMatching",
					new Object[] { subjectDN }, "No matching pattern was found in subject DN: {0}"));
		}
		Assert.isTrue(matcher.groupCount() == 1, "Regular expression must contain a single group ");
		String username = matcher.group(1);
		this.logger.debug(LogMessage.format("Extracted Principal name is '%s'", username));
		return username;
	}

	/**
	 * Sets the regular expression which will by used to extract the user name from the
	 * certificate's Subject DN.
	 * <p>
	 * It should contain a single group; for example the default expression
	 * "CN=(.*?)(?:,|$)" matches the common name field. So "CN=Jimi Hendrix, OU=..." will
	 * give a user name of "Jimi Hendrix".
	 * <p>
	 * The matches are case insensitive. So "emailAddress=(.?)," will match
	 * "EMAILADDRESS=jimi@hendrix.org, CN=..." giving a user name "jimi@hendrix.org"
	 * @param subjectDnRegex the regular expression to find in the subject
	 */
	public void setSubjectDnRegex(String subjectDnRegex) {
		Assert.hasText(subjectDnRegex, "Regular expression may not be null or empty");
		this.subjectDnPattern = Pattern.compile(subjectDnRegex, Pattern.CASE_INSENSITIVE);
	}

	/**
	 * @since 5.5
	 */
	@Override
	public void setMessageSource(MessageSource messageSource) {
		Assert.notNull(messageSource, "messageSource cannot be null");
		this.messages = new MessageSourceAccessor(messageSource);
	}

}
