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
