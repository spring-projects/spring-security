package org.springframework.security.acls.domain;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.acls.model.AccessControlEntry;
import org.springframework.security.acls.model.AuditableAccessControlEntry;

/**
 * Test class for {@link ConsoleAuditLogger}.
 *
 * @author Andrei Stefan
 */
public class AuditLoggerTests {
    //~ Instance fields ================================================================================================
    private PrintStream console;
    private ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    private ConsoleAuditLogger logger;
    private AuditableAccessControlEntry ace;

    //~ Methods ========================================================================================================

    @Before
    public void setUp() throws Exception {
        logger = new ConsoleAuditLogger();
        ace = mock(AuditableAccessControlEntry.class);
        console = System.out;
        System.setOut(new PrintStream(bytes));
    }

    @After
    public void tearDown() throws Exception {
        System.setOut(console);
        bytes.reset();
    }

    @Test
    public void nonAuditableAceIsIgnored() {
        AccessControlEntry ace = mock(AccessControlEntry.class);
        logger.logIfNeeded(true, ace);
        assertEquals(0, bytes.size());
    }

    @Test
    public void successIsNotLoggedIfAceDoesntRequireSuccessAudit() throws Exception {
        when(ace.isAuditSuccess()).thenReturn(false);
        logger.logIfNeeded(true, ace);
        assertEquals(0, bytes.size());
    }

    @Test
    public void successIsLoggedIfAceRequiresSuccessAudit() throws Exception {
        when(ace.isAuditSuccess()).thenReturn(true);

        logger.logIfNeeded(true, ace);
        assertTrue(bytes.toString().startsWith("GRANTED due to ACE"));
    }

    @Test
    public void failureIsntLoggedIfAceDoesntRequireFailureAudit() throws Exception {
        when(ace.isAuditFailure()).thenReturn(false);
        logger.logIfNeeded(false, ace);
        assertEquals(0, bytes.size());
    }

    @Test
    public void failureIsLoggedIfAceRequiresFailureAudit() throws Exception {
        when(ace.isAuditFailure()).thenReturn(true);
        logger.logIfNeeded(false, ace);
        assertTrue(bytes.toString().startsWith("DENIED due to ACE"));
    }
}
