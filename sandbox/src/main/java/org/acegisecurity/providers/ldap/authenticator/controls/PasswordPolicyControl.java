package org.acegisecurity.providers.ldap.authenticator.controls;

import javax.naming.ldap.Control;

/**
 * A Password Policy request control.
 * <p>
 * Based on the information in the corresponding internet draft on
 * LDAP password policy.
 * </p>
 *
 * @see PasswordPolicyResponseControl
 * @see <a href="http://www.ietf.org/internet-drafts/draft-behera-ldap-password-policy-09.txt">Password Policy for LDAP Directories</a>
 *
 * @author Stefan Zoerner
 * @author Luke Taylor
 *
 * @version $Id$
 *
 */
public class PasswordPolicyControl implements Control {

    /** OID of the Password Policy Control */
    public static final String OID = "1.3.6.1.4.1.42.2.27.8.5.1";

    private boolean critical;

    /**
     * Creates a non-critical (request) control.
     */
    public PasswordPolicyControl() {
        this(Control.NONCRITICAL);
    }

    /**
     * Creates a (request) control.
     * 
     * @param critical indicates whether the control is
     *                 critical for the client
     */
    public PasswordPolicyControl(boolean critical) {
        this.critical = critical;
    }

    /**
     * Returns the OID of the Password Policy Control.
     */
    public String getID() {
        return OID;
    }

    /**
     * Returns whether the control is critical for the client.
     */
    public boolean isCritical() {
        return critical;
    }

    /**
     * Retrieves the ASN.1 BER encoded value of the LDAP control. The request
     * value for this control is always empty.
     * 
     * @return always null
     */
    public byte[] getEncodedValue() {
        return null;
    }
}