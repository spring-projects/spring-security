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
package org.springframework.security.config;

import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.TransactionStatus;

import static org.mockito.Mockito.mock;

/**
 * @author Luke Taylor
 */
public class MockTransactionManager implements PlatformTransactionManager {

	public TransactionStatus getTransaction(TransactionDefinition definition) throws TransactionException {
		return mock(TransactionStatus.class);
	}

	public void commit(TransactionStatus status) throws TransactionException {
	}

	public void rollback(TransactionStatus status) throws TransactionException {
	}

}
