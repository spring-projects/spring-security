/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.context;

/**
 * Simple business object of an in-memory banking system.
 * 
 * <p>
 * We'll spare you from <code>InsufficientFundsExceptions</code> etc. After
 * all, this is intended to test security features rather than OO design!
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public interface BankManager {
    //~ Methods ================================================================

    public float getBalance(Integer accountNumber);

    public float getBankFundsUnderControl();

    public void deleteAccount(Integer accountNumber);

    public Account loadAccount(Integer accountNumber);

    public void saveAccount(Account account);

    public void transferFunds(Integer fromAccountNumber,
        Integer toAccountNumber, float amount);
}
