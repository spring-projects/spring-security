/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package sample.annotations;

import org.acegisecurity.annotation.Secured;

/**
 * <code>BankService</code> sample using Java 5 Annotations.
 *
 * @author Mark St.Godard
 * @version $Id$
 * 
 * @see org.acegisecurity.annotation.Secured
 */

@Secured({"ROLE_TELLER" })
public interface BankService {
    //~ Methods ================================================================

    /**
     * Get the account balance.
     *
     * @param accountNumber The account number
     *
     * @return The balance
     */

    @Secured({"ROLE_PERMISSION_BALANCE" })
    public float balance(String accountNumber);

    /**
     * List accounts
     *
     * @return The list of accounts
     */

    @Secured({"ROLE_PERMISSION_LIST" })
    public String[] listAccounts();
}
