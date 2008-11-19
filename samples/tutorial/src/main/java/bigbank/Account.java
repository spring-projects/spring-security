package bigbank;

/**
 * Note this class does not represent best practice, as we are failing to
 * encapsulate business logic (methods) and state in the domain object.
 * Nevertheless, this demo is intended to reflect what people usually do,
 * as opposed to what they ideally would be doing.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class Account {
    private long id = -1;
    private String holder;
    private double balance;
    private double overdraft = 100.00;

    public Account(String holder) {
        this.holder = holder;
    }

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getHolder() {
        return holder;
    }

    public void setHolder(String holder) {
        this.holder = holder;
    }

    public double getBalance() {
        return balance;
    }

    public void setBalance(double balance) {
        this.balance = balance;
    }

    public double getOverdraft() {
        return overdraft;
    }

    public void setOverdraft(double overdraft) {
        this.overdraft = overdraft;
    }

    public String toString() {
        return "Account[id=" + id + ",balance=" + balance +",holder=" + holder + ", overdraft=" + overdraft + "]";
    }
}
