/*
 * Copyright 2004-present the original author or authors.
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
import java.util.List;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
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
 * Extracts the principal from the {@link X500Principal#getName(String)} returned by
 * {@link X509Certificate#getSubjectX500Principal()} passed into
 * {@link #extractPrincipal(X509Certificate)} depending on the value of
 * {@link #setExtractPrincipalNameFromEmail(boolean)}.
 *
 * @author Max Batischev
 * @author Rob Winch
 * @since 7.0
 */
public final class SubjectX500PrincipalExtractor implements X509PrincipalExtractor, MessageSourceAware {

	private final Log logger = LogFactory.getLog(getClass());

	private static final String EMAIL_SUBJECT_DN_TYPE = "OID.1.2.840.113549.1.9.1";

	private static final String CN_SUBJECT_DN_TYPE = "CN";

	private MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	private String subjectDnType = CN_SUBJECT_DN_TYPE;

	private String x500PrincipalFormat = X500Principal.RFC2253;

	@Override
	public Object extractPrincipal(X509Certificate clientCert) {
		Assert.notNull(clientCert, "clientCert cannot be null");
		X500Principal principal = clientCert.getSubjectX500Principal();
		String subjectDN = principal.getName(this.x500PrincipalFormat);
		this.logger.debug(LogMessage.format("Subject DN is '%s'", subjectDN));
		String principalName = getSubject(subjectDN);
		this.logger.debug(LogMessage.format("Extracted Principal name is '%s'", principalName));
		return principalName;
	}

	private List<Rdn> getDns(String subjectDn) {
		try {
			return new LdapName(subjectDn).getRdns();
		}
		catch (InvalidNameException ex) {
			throw new BadCredentialsException("Failed to parse client certificate", ex);
		}
	}

	private String getSubject(String subjectDn) {
		for (Rdn rdn : getDns(subjectDn)) {
			String type = rdn.getType();
			if (this.subjectDnType.equals(type)) {
				return String.valueOf(rdn.getValue());
			}
		}
		throw new BadCredentialsException(this.messages.getMessage("SubjectX500PrincipalExtractor.noMatching",
				new Object[] { subjectDn }, "No matching pattern was found in subject DN: {0}"));
	}

	@Override
	public void setMessageSource(MessageSource messageSource) {
		Assert.notNull(messageSource, "messageSource cannot be null");
		this.messages = new MessageSourceAccessor(messageSource);
	}

	/**
	 * Sets if the principal name should be extracted from the emailAddress or CN
	 * attribute (default).
	 *
	 * By default, the format {@link X500Principal#RFC2253} is passed to
	 * {@link X500Principal#getName(String)} and the principal is extracted from the CN
	 * attribute as defined in
	 * <a href="https://datatracker.ietf.org/doc/html/rfc2253#section-2.3">Converting
	 * AttributeTypeAndValue of RFC2253</a>.
	 *
	 * If {@link #setExtractPrincipalNameFromEmail(boolean)} is {@code true}, then the
	 * format {@link X500Principal#RFC2253} is passed to
	 * {@link X500Principal#getName(String)} and the principal is extracted from the
	 * <a href="https://oid-base.com/get/1.2.840.113549.1.9.1">OID.1.2.840.113549.1.9.1
	 * (emailAddress)</a> attribute as defined in
	 * <a href="https://datatracker.ietf.org/doc/html/rfc1779#section-2.3">Section 2.3 of
	 * RFC1779</a>.
	 * @param extractPrincipalNameFromEmail whether to extract the principal from the
	 * emailAddress (default false)
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfc2253">RFC2253</a>
	 * @see <a href="https://datatracker.ietf.org/doc/html/rfC1779">RFC1779</a>
	 */
	public void setExtractPrincipalNameFromEmail(boolean extractPrincipalNameFromEmail) {
		if (extractPrincipalNameFromEmail) {
			this.subjectDnType = EMAIL_SUBJECT_DN_TYPE;
			this.x500PrincipalFormat = X500Principal.RFC1779;
		}
		else {
			this.subjectDnType = CN_SUBJECT_DN_TYPE;
			this.x500PrincipalFormat = X500Principal.RFC2253;
		}
	}

}
