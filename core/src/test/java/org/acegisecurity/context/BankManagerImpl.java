/* Copyright 2004 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.context;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;


/**
 * Implementation of {@link BankManager}.
 *
 * @author Ben Alex
 * @version $Id$
 */
public class BankManagerImpl implements BankManager {
    //~ Instance fields ========================================================

    private Map accounts = new HashMap();

    //~ Methods ================================================================

    public float getBalance(Integer accountNumber) {
        Account account = this.loadAccount(accountNumber);

        return account.getBalance();
    }

    public float getBankFundsUnderControl() {
        float total = 0;
        Iterator iter = this.accounts.keySet().iterator();

        while (iter.hasNext()) {
            Integer account = (Integer) iter.next();
            total = total + this.getBalance(account);
        }

        return total;
    }

    public void deleteAccount(Integer accountNumber) {
        this.accounts.remove(accountNumber);
    }

    public Account loadAccount(Integer accountNumber) {
        return (Account) accounts.get(accountNumber);
    }

    public void saveAccount(Account account) {
        this.accounts.put(account.getId(), account);
    }

    public void transferFunds(Integer fromAccountNumber,
        Integer toAccountNumber, float amount) {
        Account from = this.loadAccount(fromAccountNumber);
        Account to = this.loadAccount(toAccountNumber);
        from.withdraw(amount);
        to.deposit(amount);
        this.saveAccount(from);
        this.saveAccount(to);
    }
}
