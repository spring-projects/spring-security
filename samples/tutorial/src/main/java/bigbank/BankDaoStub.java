package bigbank;

import java.util.HashMap;
import java.util.Map;

public class BankDaoStub implements BankDao {
    private long id = 0;
    private final Map<Long, Account> accounts = new HashMap<Long, Account>();

    public void createOrUpdateAccount(Account account) {
        if (account.getId() == -1) {
            id++;
            account.setId(id);
        }
        accounts.put(new Long(account.getId()), account);
        System.out.println("SAVE: " + account);
    }

    public Account[] findAccounts() {
        Account[] accounts = this.accounts.values().toArray(new Account[] {});
        System.out.println("Returning " + accounts.length + " account(s):");
        for (Account account : accounts) {
            System.out.println(" > " + account);
        }
        return accounts;
    }

    public Account readAccount(Long id) {
        return accounts.get(id);
    }

}
