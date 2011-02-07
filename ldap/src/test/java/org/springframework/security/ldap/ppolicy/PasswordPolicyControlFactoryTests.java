package org.springframework.security.ldap.ppolicy;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import org.junit.*;

import javax.naming.ldap.Control;
import java.util.*;

/**
 * @author Luke Taylor
 */
public class PasswordPolicyControlFactoryTests {

    @Test
    public void returnsNullForUnrecognisedOID() throws Exception {
        PasswordPolicyControlFactory ctrlFactory = new PasswordPolicyControlFactory();
        Control wrongCtrl = mock(Control.class);

        when(wrongCtrl.getID()).thenReturn("wrongId");
        assertNull(ctrlFactory.getControlInstance(wrongCtrl));
    }

    @Test
    public void returnsControlForCorrectOID() throws Exception {
        PasswordPolicyControlFactory ctrlFactory = new PasswordPolicyControlFactory();
        Control control = mock(Control.class);

        when(control.getID()).thenReturn(PasswordPolicyControl.OID);
        when(control.getEncodedValue()).thenReturn(PasswordPolicyResponseControlTests.OPENLDAP_LOCKED_CTRL);
        Control result = ctrlFactory.getControlInstance(control);
        assertNotNull(result);
        assertTrue(Arrays.equals(PasswordPolicyResponseControlTests.OPENLDAP_LOCKED_CTRL, result.getEncodedValue()));
    }
}
