/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security;

/**
 * <code>BankService</code> sample implementation.
 *
 * @author Mark St.Godard
 * @version $Id$
 */
public class BankServiceImpl implements BankService {
    //~ Methods ========================================================================================================

    public float balance(String accountNumber) {
        return 42000000;
    }

    public String[] listAccounts() {
        return new String[] {"1", "2", "3"};
    }
}
