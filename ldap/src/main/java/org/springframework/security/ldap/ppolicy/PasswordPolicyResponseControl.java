/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
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
import org.springframework.dao.DataRetrievalFailureException;


/**
 * Represents the response control received when a <tt>PasswordPolicyControl</tt> is used when binding to a
 * directory. Currently tested with the OpenLDAP 2.3.19 implementation of the LDAP Password Policy Draft.  It extends
 * the request control with the control specific data. This is accomplished by the properties <tt>timeBeforeExpiration</tt>,
 * <tt>graceLoginsRemaining</tt>.
 * <p>
 *
 *
 * @author Stefan Zoerner
 * @author Luke Taylor
 *
 * @see org.springframework.security.ldap.ppolicy.PasswordPolicyControl
 * @see <a href="http://www.ibm.com/developerworks/tivoli/library/t-ldap-controls/">Stefan Zoerner's IBM developerworks
 *      article on LDAP controls.</a>
 */
public class PasswordPolicyResponseControl extends PasswordPolicyControl {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(PasswordPolicyResponseControl.class);

    //~ Instance fields ================================================================================================

    private final byte[] encodedValue;

    private PasswordPolicyErrorStatus errorStatus;

    private int graceLoginsRemaining = Integer.MAX_VALUE;
    private int timeBeforeExpiration = Integer.MAX_VALUE;

    //~ Constructors ===================================================================================================

    /**
     * Decodes the Ber encoded control data. The ASN.1 value of the control data is:<pre>
     *    PasswordPolicyResponseValue ::= SEQUENCE {       warning [0] CHOICE {
     *           timeBeforeExpiration [0] INTEGER (0 .. maxInt),
     *           graceAuthNsRemaining [1] INTEGER (0 .. maxInt) } OPTIONAL,       error   [1] ENUMERATED {
     *           passwordExpired             (0),          accountLocked               (1),
     *           changeAfterReset            (2),          passwordModNotAllowed       (3),
     *           mustSupplyOldPassword       (4),          insufficientPasswordQuality (5),
     *           passwordTooShort            (6),          passwordTooYoung            (7),
     *           passwordInHistory           (8) } OPTIONAL }</pre>
     *
     */
    public PasswordPolicyResponseControl(byte[] encodedValue) {
        this.encodedValue = encodedValue;

        //PPolicyDecoder decoder = new JLdapDecoder();
        PPolicyDecoder decoder = new NetscapeDecoder();

        try {
            decoder.decode();
        } catch (IOException e) {
            throw new DataRetrievalFailureException("Failed to parse control value", e);
        }
    }

    //~ Methods ========================================================================================================

    /**
     * Returns the unchanged value of the response control.  Returns the unchanged value of the response
     * control as byte array.
     */
    public byte[] getEncodedValue() {
        return encodedValue;
    }

    public PasswordPolicyErrorStatus getErrorStatus() {
        return errorStatus;
    }

    /**
     * Returns the graceLoginsRemaining.
     *
     * @return Returns the graceLoginsRemaining.
     */
    public int getGraceLoginsRemaining() {
        return graceLoginsRemaining;
    }

    /**
     * Returns the timeBeforeExpiration.
     *
     * @return Returns the time before expiration in seconds
     */
    public int getTimeBeforeExpiration() {
        return timeBeforeExpiration;
    }

    /**
     * Checks whether an error is present.
     *
     * @return true, if an error is present
     */
    public boolean hasError() {
        return errorStatus != null;
    }

    /**
     * Checks whether a warning is present.
     *
     * @return true, if a warning is present
     */
    public boolean hasWarning() {
        return (graceLoginsRemaining != Integer.MAX_VALUE) || (timeBeforeExpiration != Integer.MAX_VALUE);
    }

    public boolean isExpired() {
        return errorStatus == PasswordPolicyErrorStatus.PASSWORD_EXPIRED;
    }

    public boolean isChangeAfterReset() {
        return errorStatus == PasswordPolicyErrorStatus.CHANGE_AFTER_RESET;
    }

    public boolean isUsingGraceLogins() {
        return graceLoginsRemaining < Integer.MAX_VALUE;
    }

    /**
     * Determines whether an account locked error has been returned.
     *
     * @return true if the account is locked.
     */
    public boolean isLocked() {
        return errorStatus == PasswordPolicyErrorStatus.ACCOUNT_LOCKED;
    }

    /**
     * Create a textual representation containing error and warning messages, if any are present.
     *
     * @return error and warning messages
     */
    public String toString() {
        StringBuilder sb = new StringBuilder("PasswordPolicyResponseControl");

        if (hasError()) {
            sb.append(", error: ").append(errorStatus.getDefaultMessage());
        }

        if (graceLoginsRemaining != Integer.MAX_VALUE) {
            sb.append(", warning: ").append(graceLoginsRemaining).append(" grace logins remain");
        }

        if (timeBeforeExpiration != Integer.MAX_VALUE) {
            sb.append(", warning: time before expiration is ").append(timeBeforeExpiration);
        }

        if (!hasError() && !hasWarning()) {
            sb.append(" (no error, no warning)");
        }

        return sb.toString();
    }

    //~ Inner Interfaces ===============================================================================================

    private interface PPolicyDecoder {
        void decode() throws IOException;
    }

    //~ Inner Classes ==================================================================================================

    /**
     * Decoder based on Netscape ldapsdk library
     */
    private class NetscapeDecoder implements PPolicyDecoder {
        public void decode() throws IOException {
            int[] bread = {0};
            BERSequence seq = (BERSequence) BERElement.getElement(new SpecificTagDecoder(),
                    new ByteArrayInputStream(encodedValue), bread);

            int size = seq.size();

            if (logger.isDebugEnabled()) {
                logger.debug("PasswordPolicyResponse, ASN.1 sequence has " + size + " elements");
            }

            for (int i = 0; i < seq.size(); i++) {
                BERTag elt = (BERTag) seq.elementAt(i);

                int tag = elt.getTag() & 0x1F;

                if (tag == 0) {
                    BERChoice warning = (BERChoice) elt.getValue();

                    BERTag content = (BERTag) warning.getValue();
                    int value = ((BERInteger) content.getValue()).getValue();

                    if ((content.getTag() & 0x1F) == 0) {
                        timeBeforeExpiration = value;
                    } else {
                        graceLoginsRemaining = value;
                    }
                } else if (tag == 1) {
                    BERIntegral error = (BERIntegral) elt.getValue();
                    errorStatus = PasswordPolicyErrorStatus.values()[error.getValue()];
                }
            }
        }

        class SpecificTagDecoder extends BERTagDecoder {
            /** Allows us to remember which of the two options we're decoding */
            private Boolean inChoice = null;

            public BERElement getElement(BERTagDecoder decoder, int tag, InputStream stream, int[] bytesRead,
                boolean[] implicit) throws IOException {
                tag &= 0x1F;
                implicit[0] = false;

                if (tag == 0) {
                    // Either the choice or the time before expiry within it
                    if (inChoice == null) {
                        setInChoice(true);

                        // Read the choice length from the stream (ignored)
                        BERElement.readLengthOctets(stream, bytesRead);

                        int[] componentLength = new int[1];
                        BERElement choice = new BERChoice(decoder, stream, componentLength);
                        bytesRead[0] += componentLength[0];

                        // inChoice = null;
                        return choice;
                    } else {
                        // Must be time before expiry
                        return new BERInteger(stream, bytesRead);
                    }
                } else if (tag == 1) {
                    // Either the graceLogins or the error enumeration.
                    if (inChoice == null) {
                        // The enumeration
                        setInChoice(false);

                        return new BEREnumerated(stream, bytesRead);
                    } else {
                        if (inChoice.booleanValue()) {
                            // graceLogins
                            return new BERInteger(stream, bytesRead);
                        }
                    }
                }

                throw new DataRetrievalFailureException("Unexpected tag " + tag);
            }

            private void setInChoice(boolean inChoice) {
                this.inChoice = Boolean.valueOf(inChoice);
            }
        }
    }

/** Decoder based on the OpenLDAP/Novell JLDAP library */

//    private class JLdapDecoder implements PPolicyDecoder {
//
//        public void decode() throws IOException {
//
//            LBERDecoder decoder = new LBERDecoder();
//
//            ASN1Sequence seq = (ASN1Sequence)decoder.decode(encodedValue);
//
//            if(seq == null) {
//
//            }
//
//            int size = seq.size();
//
//            if(logger.isDebugEnabled()) {
//                logger.debug("PasswordPolicyResponse, ASN.1 sequence has " +
//                        size + " elements");
//            }
//
//            for(int i=0; i < size; i++) {
//
//                ASN1Tagged taggedObject = (ASN1Tagged)seq.get(i);
//
//                int tag = taggedObject.getIdentifier().getTag();
//
//                ASN1OctetString value = (ASN1OctetString)taggedObject.taggedValue();
//                byte[] content = value.byteValue();
//
//                if(tag == 0) {
//                    parseWarning(content, decoder);
//
//                } else if(tag == 1) {
//                    // Error: set the code to the value
//                    errorCode = content[0];
//                }
//            }
//        }
//
//        private void parseWarning(byte[] content, LBERDecoder decoder) {
//            // It's the warning (choice). Parse the number and set either the
//            // expiry time or number of logins remaining.
//            ASN1Tagged taggedObject = (ASN1Tagged)decoder.decode(content);
//            int contentTag = taggedObject.getIdentifier().getTag();
//            content = ((ASN1OctetString)taggedObject.taggedValue()).byteValue();
//            int number;
//
//            try {
//                number = ((Long)decoder.decodeNumeric(new ByteArrayInputStream(content), content.length)).intValue();
//            } catch(IOException e) {
//                throw new LdapDataAccessException("Failed to parse number ", e);
//            }
//
//            if(contentTag == 0) {
//                timeBeforeExpiration = number;
//            } else if (contentTag == 1) {
//                graceLoginsRemaining = number;
//            }
//        }
//    }
}
