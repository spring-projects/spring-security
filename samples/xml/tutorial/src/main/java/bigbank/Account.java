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

/**
 * Note this class does not represent best practice, as we are failing to encapsulate
 * business logic (methods) and state in the domain object. Nevertheless, this demo is
 * intended to reflect what people usually do, as opposed to what they ideally would be
 * doing.
 *
 * @author Ben Alex
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
		return "Account[id=" + id + ",balance=" + balance + ",holder=" + holder
				+ ", overdraft=" + overdraft + "]";
	}
}
