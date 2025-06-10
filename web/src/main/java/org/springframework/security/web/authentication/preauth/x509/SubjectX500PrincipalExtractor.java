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

import javax.security.auth.x500.X500Principal;

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
 * Obtains the principal from a certificate using RFC2253 and RFC1779 formats. By default,
 * RFC2253 is used: DN is extracted from CN. If extractPrincipalNameFromEmail is true then
 * format RFC1779 will be used: DN is extracted from EMAIlADDRESS.
 *
 * @author Max Batischev
 * @author Rob Winch
 * @since 7.0
 */
public final class SubjectX500PrincipalExtractor implements X509PrincipalExtractor, MessageSourceAware {

	private final Log logger = LogFactory.getLog(getClass());

	private static final Pattern EMAIL_SUBJECT_DN_PATTERN = Pattern.compile("OID.1.2.840.113549.1.9.1=(.*?)(?:,|$)",
			Pattern.CASE_INSENSITIVE);

	private static final Pattern CN_SUBJECT_DN_PATTERN = Pattern.compile("CN=(.*?)(?:,|$)", Pattern.CASE_INSENSITIVE);

	private MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	private Pattern subjectDnPattern = CN_SUBJECT_DN_PATTERN;

	private String x500PrincipalFormat = X500Principal.RFC2253;

	@Override
	public Object extractPrincipal(X509Certificate clientCert) {
		Assert.notNull(clientCert, "clientCert cannot be null");
		X500Principal principal = clientCert.getSubjectX500Principal();
		String subjectDN = principal.getName(this.x500PrincipalFormat);
		this.logger.debug(LogMessage.format("Subject DN is '%s'", subjectDN));
		Matcher matcher = this.subjectDnPattern.matcher(subjectDN);
		if (!matcher.find()) {
			throw new BadCredentialsException(this.messages.getMessage("SubjectX500PrincipalExtractor.noMatching",
					new Object[] { subjectDN }, "No matching pattern was found in subject DN: {0}"));
		}
		String principalName = matcher.group(1);
		this.logger.debug(LogMessage.format("Extracted Principal name is '%s'", principalName));
		return principalName;
	}

	@Override
	public void setMessageSource(MessageSource messageSource) {
		Assert.notNull(messageSource, "messageSource cannot be null");
		this.messages = new MessageSourceAccessor(messageSource);
	}

	/**
	 * If true then DN will be extracted from EMAIlADDRESS, defaults to {@code false}
	 * @param extractPrincipalNameFromEmail whether to extract DN from EMAIlADDRESS
	 */
	public void setExtractPrincipalNameFromEmail(boolean extractPrincipalNameFromEmail) {
		if (extractPrincipalNameFromEmail) {
			this.subjectDnPattern = EMAIL_SUBJECT_DN_PATTERN;
			this.x500PrincipalFormat = X500Principal.RFC1779;
		}
		else {
			this.subjectDnPattern = CN_SUBJECT_DN_PATTERN;
			this.x500PrincipalFormat = X500Principal.RFC2253;
		}
	}

}
