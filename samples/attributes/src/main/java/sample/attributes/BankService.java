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

package sample.attributes;

/**
 * DOCUMENT ME!
 *
 * @author Cameron Braid
 * @author Ben Alex
 * @version $Id$
 *
 * @@SecurityConfig("ROLE_TELLER")
 */
public interface BankService {
    //~ Methods ================================================================

    /**
     * The SecurityConfig below will be merged with the interface-level
     * SecurityConfig above by Commons Attributes. ie: this is equivalent to
     * defining BankService=ROLE_TELLER,ROLE_PERMISSION_BALANACE in  the bean
     * context.
     *
     * @return DOCUMENT ME!
     *
     * @@SecurityConfig("ROLE_PERMISSION_BALANCE")
     */
    public float balance(String accountNumber);

    /**
     * The SecurityConfig below will be merged with the interface-level
     * SecurityConfig above by Commons Attributes. ie: this is equivalent to
     * defining BankService=ROLE_TELLER,ROLE_PERMISSION_LIST in  the bean
     * context.
     *
     * @return DOCUMENT ME!
     *
     * @@SecurityConfig("ROLE_PERMISSION_LIST")
     */
    public String[] listAccounts();
}
