/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.context;

/**
 * Models a bank account.
 */
public class Account {
    //~ Instance fields ========================================================

    private Integer id;
    private String owningUserName;
    private float balance;

    //~ Constructors ===========================================================

    public Account(Integer id, String owningUserName) {
        this.id = id;
        this.owningUserName = owningUserName;
    }

    public Account(int id, String owningUserName) {
        this.id = new Integer(id);
        this.owningUserName = owningUserName;
    }

    private Account() {
        super();
    }

    //~ Methods ================================================================

    public float getBalance() {
        return this.balance;
    }

    public Integer getId() {
        return this.id;
    }

    public String getOwningUserName() {
        return this.owningUserName;
    }

    public void deposit(float amount) {
        this.balance = this.balance + amount;
    }

    public void withdraw(float amount) {
        this.balance = this.balance - amount;
    }
}
