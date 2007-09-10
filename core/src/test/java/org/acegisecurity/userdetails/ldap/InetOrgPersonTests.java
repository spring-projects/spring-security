package org.acegisecurity.userdetails.ldap;

import junit.framework.TestCase;

import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DistinguishedName;

/**
 * @author Luke Taylor
 * @version $Id$
 */
public class InetOrgPersonTests extends TestCase {

    public void testUsernameIsMappedFromContextUidIfNotSet() {
        InetOrgPerson.Essence essence = new InetOrgPerson.Essence(createUserContext());
        InetOrgPerson p = (InetOrgPerson) essence.createUserDetails();

        assertEquals("ghengis", p.getUsername());

    }

    public void testUsernameIsDifferentFromContextUidIfSet() {
        InetOrgPerson.Essence essence = new InetOrgPerson.Essence(createUserContext());
        essence.setUsername("joe");
        InetOrgPerson p = (InetOrgPerson) essence.createUserDetails();

        assertEquals("joe", p.getUsername());
        assertEquals("ghengis", p.getUid());
    }

    public void testAttributesMapCorrectlyFromContext() {
        InetOrgPerson.Essence essence = new InetOrgPerson.Essence(createUserContext());
        InetOrgPerson p = (InetOrgPerson) essence.createUserDetails();

        assertEquals("ghengis@mongolia", p.getMail());
        assertEquals("Khan", p.getSn());
        assertEquals("Ghengis Khan", p.getCn()[0]);
        assertEquals("00001", p.getEmployeeNumber());
        assertEquals("West", p.getDestinationIndicator());
    }

    public void testPasswordIsSetFromContextUserPassword() {
        InetOrgPerson.Essence essence = new InetOrgPerson.Essence(createUserContext());
        InetOrgPerson p = (InetOrgPerson) essence.createUserDetails();

        assertEquals("pillage", p.getPassword());

    }

    private DirContextAdapter createUserContext() {
        DirContextAdapter ctx = new DirContextAdapter();

        ctx.setDn(new DistinguishedName("ignored=ignored"));
        ctx.setAttributeValue("uid", "ghengis");
        ctx.setAttributeValue("userPassword", "pillage");
        ctx.setAttributeValue("mail", "ghengis@mongolia");
        ctx.setAttributeValue("cn", "Ghengis Khan");
        ctx.setAttributeValue("sn", "Khan");
        ctx.setAttributeValue("employeeNumber", "00001");
        ctx.setAttributeValue("destinationIndicator", "West");
        ctx.setAttributeValue("o", "Hordes");

        return ctx;
    }

}
