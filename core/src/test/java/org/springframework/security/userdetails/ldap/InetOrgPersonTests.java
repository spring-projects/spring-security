package org.springframework.security.userdetails.ldap;

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

        assertEquals("HORS1", p.getCarLicense());
        assertEquals("ghengis@mongolia", p.getMail());
        assertEquals("Khan", p.getSn());
        assertEquals("Ghengis Khan", p.getCn()[0]);
        assertEquals("00001", p.getEmployeeNumber());
        assertEquals("+442075436521", p.getTelephoneNumber());
        assertEquals("Steppes", p.getHomePostalAddress());        
        assertEquals("+467575436521", p.getHomePhone());
        assertEquals("Hordes", p.getO());
        assertEquals("Horde1", p.getOu());
        assertEquals("On the Move", p.getPostalAddress());
        assertEquals("Changes Frequently", p.getPostalCode());
        assertEquals("Yurt 1", p.getRoomNumber());
        assertEquals("Westward Avenue", p.getStreet());
        assertEquals("Scary", p.getDescription());
        assertEquals("Ghengis McCann", p.getDisplayName());
        assertEquals("G", p.getInitials());
    }

    public void testPasswordIsSetFromContextUserPassword() {
        InetOrgPerson.Essence essence = new InetOrgPerson.Essence(createUserContext());
        InetOrgPerson p = (InetOrgPerson) essence.createUserDetails();

        assertEquals("pillage", p.getPassword());
    }
    
    public void testMappingBackToContextMatchesOriginalData() {
        DirContextAdapter ctx1 = createUserContext();
        DirContextAdapter ctx2 = new DirContextAdapter();
        ctx1.setAttributeValues("objectclass", new String[] {"top", "person", "organizationalPerson", "inetOrgPerson"});
        ctx2.setDn(new DistinguishedName("ignored=ignored"));
        InetOrgPerson p = (InetOrgPerson) (new InetOrgPerson.Essence(ctx1)).createUserDetails();
        p.populateContext(ctx2);
        
        assertEquals(ctx1, ctx2);
    }

    public void testCopyMatchesOriginalData() {
        DirContextAdapter ctx1 = createUserContext();
        DirContextAdapter ctx2 = new DirContextAdapter();
        ctx2.setDn(new DistinguishedName("ignored=ignored"));
        ctx1.setAttributeValues("objectclass", new String[] {"top", "person", "organizationalPerson", "inetOrgPerson"});
        InetOrgPerson p = (InetOrgPerson) (new InetOrgPerson.Essence(ctx1)).createUserDetails();
        InetOrgPerson p2 = (InetOrgPerson) new InetOrgPerson.Essence(p).createUserDetails();
        p2.populateContext(ctx2);

        assertEquals(ctx1, ctx2);        
    }    
    
    private DirContextAdapter createUserContext() {
        DirContextAdapter ctx = new DirContextAdapter();

        ctx.setDn(new DistinguishedName("ignored=ignored"));
        ctx.setAttributeValue("uid", "ghengis");
        ctx.setAttributeValue("userPassword", "pillage");
        ctx.setAttributeValue("carLicense", "HORS1");
        ctx.setAttributeValue("cn", "Ghengis Khan");
        ctx.setAttributeValue("description", "Scary");
        ctx.setAttributeValue("destinationIndicator", "West");
        ctx.setAttributeValue("displayName", "Ghengis McCann");
        ctx.setAttributeValue("homePhone", "+467575436521");
        ctx.setAttributeValue("initials", "G");
        ctx.setAttributeValue("employeeNumber", "00001");
        ctx.setAttributeValue("homePostalAddress", "Steppes");
        ctx.setAttributeValue("mail", "ghengis@mongolia");
        ctx.setAttributeValue("mobile", "always");
        ctx.setAttributeValue("o", "Hordes");
        ctx.setAttributeValue("ou", "Horde1");
        ctx.setAttributeValue("postalAddress", "On the Move");
        ctx.setAttributeValue("postalCode", "Changes Frequently");
        ctx.setAttributeValue("roomNumber", "Yurt 1");
        ctx.setAttributeValue("roomNumber", "Yurt 1");
        ctx.setAttributeValue("sn", "Khan");
        ctx.setAttributeValue("street", "Westward Avenue");
        ctx.setAttributeValue("telephoneNumber", "+442075436521");

        return ctx;
    }

}
