package org.springframework.security.config;

import static org.mockito.Mockito.mock;

import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.TransactionException;
import org.springframework.transaction.TransactionStatus;

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
