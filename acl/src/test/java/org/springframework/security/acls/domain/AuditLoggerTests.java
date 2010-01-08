package org.springframework.security.acls.domain;

import static org.junit.Assert.*;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;

import org.jmock.Expectations;
import org.jmock.Mockery;
import org.jmock.integration.junit4.JUnit4Mockery;
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
    private Mockery jmock = new JUnit4Mockery();
    private PrintStream console;
    private ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    private ConsoleAuditLogger logger;
    private AuditableAccessControlEntry ace;
    private Expectations aceRequiresAudit;
    private Expectations aceDoesntRequireAudit;

    //~ Methods ========================================================================================================

    @Before
    public void setUp() throws Exception {
        logger = new ConsoleAuditLogger();
        ace = jmock.mock(AuditableAccessControlEntry.class);
        aceRequiresAudit = new Expectations() {{
            allowing(ace).isAuditSuccess(); will(returnValue(true));
            allowing(ace).isAuditFailure(); will(returnValue(true));
        }};
        aceDoesntRequireAudit = new Expectations() {{
            allowing(ace).isAuditSuccess(); will(returnValue(false));
            allowing(ace).isAuditFailure(); will(returnValue(false));
        }};

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
        AccessControlEntry ace = jmock.mock(AccessControlEntry.class);
        logger.logIfNeeded(true, ace);
        assertEquals(0, bytes.size());
    }

    @Test
    public void successIsNotLoggedIfAceDoesntRequireSuccessAudit() throws Exception {
        jmock.checking(aceDoesntRequireAudit);
        logger.logIfNeeded(true, ace);
        assertEquals(0, bytes.size());
    }

    @Test
    public void successIsLoggedIfAceRequiresSuccessAudit() throws Exception {
        jmock.checking(aceRequiresAudit);
        logger.logIfNeeded(true, ace);
        assertTrue(bytes.toString().startsWith("GRANTED due to ACE"));
    }

    @Test
    public void failureIsntLoggedIfAceDoesntRequireFailureAudit() throws Exception {
        jmock.checking(aceDoesntRequireAudit);
        logger.logIfNeeded(false, ace);
        assertEquals(0, bytes.size());
    }

    @Test
    public void failureIsLoggedIfAceRequiresFailureAudit() throws Exception {
        jmock.checking(aceRequiresAudit);
        logger.logIfNeeded(false, ace);
        assertTrue(bytes.toString().startsWith("DENIED due to ACE"));
    }
}
