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
 */
public class BankServiceImpl implements BankService {
    //~ Methods ================================================================

    public float balance(String accountNumber) {
        return 42000000;
    }

    public String[] listAccounts() {
        return new String[] {"1", "2", "3"};
    }
}
