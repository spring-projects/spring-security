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

package net.sf.acegisecurity.runas;

import net.sf.acegisecurity.context.Account;
import net.sf.acegisecurity.context.BankManager;

import org.springframework.beans.factory.InitializingBean;


/**
 * Acts as the "public facade" to a <code>BankManager</code>.
 * 
 * <P>
 * The security configuration of this, the public facade, specifies authorities
 * that should be held by the end user. The security configuration of the
 * "backend", which is not accessible to the general public, specifies certain
 * authorities that are granted by the RunAsManagerImpl.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class BankManagerPublicFacade implements BankManager, InitializingBean {
    //~ Instance fields ========================================================

    private BankManager backend;

    //~ Methods ================================================================

    public void setBackend(BankManager backend) {
        this.backend = backend;
    }

    public BankManager getBackend() {
        return backend;
    }

    public float getBalance(Integer accountNumber) {
        return backend.getBalance(accountNumber);
    }

    public float getBankFundsUnderControl() {
        return backend.getBankFundsUnderControl();
    }

    public void afterPropertiesSet() throws Exception {
        if (backend == null) {
            throw new IllegalArgumentException(
                "A backend BankManager implementation is required");
        }
    }

    public void deleteAccount(Integer accountNumber) {
        backend.deleteAccount(accountNumber);
    }

    public Account loadAccount(Integer accountNumber) {
        return backend.loadAccount(accountNumber);
    }

    public void saveAccount(Account account) {
        backend.saveAccount(account);
    }

    public void transferFunds(Integer fromAccountNumber,
        Integer toAccountNumber, float amount) {
        backend.transferFunds(fromAccountNumber, toAccountNumber, amount);
    }
}
