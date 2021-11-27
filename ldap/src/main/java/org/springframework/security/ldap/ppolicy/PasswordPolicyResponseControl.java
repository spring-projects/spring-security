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

package org.springframework.security.ldap.ppolicy;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import netscape.ldap.ber.stream.BERChoice;
import netscape.ldap.ber.stream.BERElement;
import netscape.ldap.ber.stream.BEREnumerated;
import netscape.ldap.ber.stream.BERInteger;
import netscape.ldap.ber.stream.BERIntegral;
import netscape.ldap.ber.stream.BERSequence;
import netscape.ldap.ber.stream.BERTag;
import netscape.ldap.ber.stream.BERTagDecoder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.dao.DataRetrievalFailureException;

/**
 * Represents the response control received when a <tt>PasswordPolicyControl</tt> is used
 * when binding to a directory. Currently tested with the OpenLDAP 2.3.19 implementation
 * of the LDAP Password Policy Draft. It extends the request control with the control
 * specific data. This is accomplished by the properties <tt>timeBeforeExpiration</tt>,
 * <tt>graceLoginsRemaining</tt>.
 * <p>
 *
 * @author Stefan Zoerner
 * @author Luke Taylor
 * @see org.springframework.security.ldap.ppolicy.PasswordPolicyControl
 * @see <a href=
 * "https://www.ibm.com/developerworks/tivoli/library/t-ldap-controls/">Stefan Zoerner's
 * IBM developerworks article on LDAP controls.</a>
 */
public class PasswordPolicyResponseControl extends PasswordPolicyControl {

	private static final Log logger = LogFactory.getLog(PasswordPolicyResponseControl.class);

	private final byte[] encodedValue;

	private PasswordPolicyErrorStatus errorStatus;

	private int graceLoginsRemaining = Integer.MAX_VALUE;

	private int timeBeforeExpiration = Integer.MAX_VALUE;

	/**
	 * Decodes the Ber encoded control data. The ASN.1 value of the control data is:
	 *
	 * <pre>
	 *    PasswordPolicyResponseValue ::= SEQUENCE {       warning [0] CHOICE {
	 *           timeBeforeExpiration [0] INTEGER (0 .. maxInt),
	 *           graceAuthNsRemaining [1] INTEGER (0 .. maxInt) } OPTIONAL,       error   [1] ENUMERATED {
	 *           passwordExpired             (0),          accountLocked               (1),
	 *           changeAfterReset            (2),          passwordModNotAllowed       (3),
	 *           mustSupplyOldPassword       (4),          insufficientPasswordQuality (5),
	 *           passwordTooShort            (6),          passwordTooYoung            (7),
	 *           passwordInHistory           (8) } OPTIONAL }
	 * </pre>
	 *
	 */
	public PasswordPolicyResponseControl(byte[] encodedValue) {
		this.encodedValue = encodedValue;
		PPolicyDecoder decoder = new NetscapeDecoder();
		try {
			decoder.decode();
		}
		catch (IOException ex) {
			throw new DataRetrievalFailureException("Failed to parse control value", ex);
		}
	}

	/**
	 * Returns the unchanged value of the response control. Returns the unchanged value of
	 * the response control as byte array.
	 */
	@Override
	public byte[] getEncodedValue() {
		return this.encodedValue;
	}

	public PasswordPolicyErrorStatus getErrorStatus() {
		return this.errorStatus;
	}

	/**
	 * Returns the graceLoginsRemaining.
	 * @return Returns the graceLoginsRemaining.
	 */
	public int getGraceLoginsRemaining() {
		return this.graceLoginsRemaining;
	}

	/**
	 * Returns the timeBeforeExpiration.
	 * @return Returns the time before expiration in seconds
	 */
	public int getTimeBeforeExpiration() {
		return this.timeBeforeExpiration;
	}

	/**
	 * Checks whether an error is present.
	 * @return true, if an error is present
	 */
	public boolean hasError() {
		return this.errorStatus != null;
	}

	/**
	 * Checks whether a warning is present.
	 * @return true, if a warning is present
	 */
	public boolean hasWarning() {
		return (this.graceLoginsRemaining != Integer.MAX_VALUE) || (this.timeBeforeExpiration != Integer.MAX_VALUE);
	}

	public boolean isExpired() {
		return this.errorStatus == PasswordPolicyErrorStatus.PASSWORD_EXPIRED;
	}

	public boolean isChangeAfterReset() {
		return this.errorStatus == PasswordPolicyErrorStatus.CHANGE_AFTER_RESET;
	}

	public boolean isUsingGraceLogins() {
		return this.graceLoginsRemaining < Integer.MAX_VALUE;
	}

	/**
	 * Determines whether an account locked error has been returned.
	 * @return true if the account is locked.
	 */
	public boolean isLocked() {
		return this.errorStatus == PasswordPolicyErrorStatus.ACCOUNT_LOCKED;
	}

	/**
	 * Create a textual representation containing error and warning messages, if any are
	 * present.
	 * @return error and warning messages
	 */
	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append(getClass().getSimpleName()).append(" [");
		if (hasError()) {
			sb.append("error=").append(this.errorStatus.getDefaultMessage()).append("; ");
		}
		if (this.graceLoginsRemaining != Integer.MAX_VALUE) {
			sb.append("warning=").append(this.graceLoginsRemaining).append(" grace logins remain; ");
		}
		if (this.timeBeforeExpiration != Integer.MAX_VALUE) {
			sb.append("warning=time before expiration is ").append(this.timeBeforeExpiration).append("; ");
		}
		if (!hasError() && !hasWarning()) {
			sb.append("(no error, no warning)");
		}
		sb.append("]");
		return sb.toString();
	}

	private interface PPolicyDecoder {

		void decode() throws IOException;

	}

	/**
	 * Decoder based on Netscape ldapsdk library
	 */
	private class NetscapeDecoder implements PPolicyDecoder {

		@Override
		public void decode() throws IOException {
			int[] bread = { 0 };
			BERSequence seq = (BERSequence) BERElement.getElement(new SpecificTagDecoder(),
					new ByteArrayInputStream(PasswordPolicyResponseControl.this.encodedValue), bread);
			int size = seq.size();
			if (logger.isDebugEnabled()) {
				logger.debug(LogMessage.format("Received PasswordPolicyResponse whose ASN.1 sequence has %d elements",
						size));
			}
			for (int i = 0; i < seq.size(); i++) {
				BERTag elt = (BERTag) seq.elementAt(i);
				int tag = elt.getTag() & 0x1F;
				if (tag == 0) {
					BERChoice warning = (BERChoice) elt.getValue();
					BERTag content = (BERTag) warning.getValue();
					int value = ((BERInteger) content.getValue()).getValue();
					if ((content.getTag() & 0x1F) == 0) {
						PasswordPolicyResponseControl.this.timeBeforeExpiration = value;
					}
					else {
						PasswordPolicyResponseControl.this.graceLoginsRemaining = value;
					}
				}
				else if (tag == 1) {
					BERIntegral error = (BERIntegral) elt.getValue();
					PasswordPolicyResponseControl.this.errorStatus = PasswordPolicyErrorStatus.values()[error
							.getValue()];
				}
			}
		}

		class SpecificTagDecoder extends BERTagDecoder {

			/** Allows us to remember which of the two options we're decoding */
			private Boolean inChoice = null;

			@Override
			public BERElement getElement(BERTagDecoder decoder, int tag, InputStream stream, int[] bytesRead,
					boolean[] implicit) throws IOException {
				tag &= 0x1F;
				implicit[0] = false;
				if (tag == 0) {
					// Either the choice or the time before expiry within it
					if (this.inChoice == null) {
						setInChoice(true);
						// Read the choice length from the stream (ignored)
						BERElement.readLengthOctets(stream, bytesRead);
						int[] componentLength = new int[1];
						BERElement choice = new BERChoice(decoder, stream, componentLength);
						bytesRead[0] += componentLength[0];
						// inChoice = null;
						return choice;
					}
					else {
						// Must be time before expiry
						return new BERInteger(stream, bytesRead);
					}
				}
				else if (tag == 1) {
					// Either the graceLogins or the error enumeration.
					if (this.inChoice == null) {
						// The enumeration
						setInChoice(false);
						return new BEREnumerated(stream, bytesRead);
					}
					else {
						if (this.inChoice) {
							// graceLogins
							return new BERInteger(stream, bytesRead);
						}
					}
				}
				throw new DataRetrievalFailureException("Unexpected tag " + tag);
			}

			private void setInChoice(boolean inChoice) {
				this.inChoice = inChoice;
			}

		}

	}

}
