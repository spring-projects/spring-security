/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package sample.attributes;

/**
 * DOCUMENT ME!
 *
 * @author Cameron Braid
 * @author Ben Alex
 * @version $Id$
 *
 * @@SecurityConfig("ROLE_TELLER")
 */
public interface BankService {
    //~ Methods ================================================================

    /**
     * The SecurityConfig below will be merged with the interface-level
     * SecurityConfig above by Commons Attributes. ie: this is equivalent to
     * defining BankService=ROLE_TELLER,ROLE_PERMISSION_BALANACE in  the bean
     * context.
     *
     * @return DOCUMENT ME!
     *
     * @@SecurityConfig("ROLE_PERMISSION_BALANCE")
     */
    public float balance(String accountNumber);

    /**
     * The SecurityConfig below will be merged with the interface-level
     * SecurityConfig above by Commons Attributes. ie: this is equivalent to
     * defining BankService=ROLE_TELLER,ROLE_PERMISSION_LIST in  the bean
     * context.
     *
     * @return DOCUMENT ME!
     *
     * @@SecurityConfig("ROLE_PERMISSION_LIST")
     */
    public String[] listAccounts();
}
