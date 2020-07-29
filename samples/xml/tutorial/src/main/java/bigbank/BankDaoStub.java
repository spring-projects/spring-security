/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package bigbank;

import java.util.HashMap;
import java.util.Map;

public class BankDaoStub implements BankDao {
	private long id = 0;
	private final Map<Long, Account> accounts = new HashMap<>();

	public void createOrUpdateAccount(Account account) {
		if (account.getId() == -1) {
			id++;
			account.setId(id);
		}
		accounts.put(account.getId(), account);
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
