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
