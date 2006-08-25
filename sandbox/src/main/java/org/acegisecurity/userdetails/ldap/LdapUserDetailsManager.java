package org.acegisecurity.userdetails.ldap;

import org.acegisecurity.userdetails.UserDetailsManager;
import org.acegisecurity.userdetails.UserDetails;
import org.acegisecurity.userdetails.UsernameNotFoundException;
import org.acegisecurity.ldap.LdapUtils;
import org.acegisecurity.ldap.ContextSourceInitialDirContextFactory;
import org.acegisecurity.providers.encoding.PasswordEncoder;
import org.acegisecurity.providers.ldap.authenticator.LdapShaPasswordEncoder;
import org.springframework.dao.DataAccessException;
import org.springframework.util.Assert;
import org.springframework.beans.BeanWrapperImpl;
import net.sf.ldaptemplate.ContextSource;
import net.sf.ldaptemplate.LdapTemplate;
import net.sf.ldaptemplate.EntryNotFoundException;
import net.sf.ldaptemplate.ContextMapper;
import net.sf.ldaptemplate.support.DistinguishedName;
import net.sf.ldaptemplate.support.DirContextOperations;
import net.sf.ldaptemplate.support.DirContextAdapter;

import javax.naming.Context;
import java.util.*;

/**
 * UserDetails manager. Based on the "Person" sample dao from spring-ldap.
 *
 * @author Luke
 * @version $Id$
 */
public class LdapUserDetailsManager implements UserDetailsManager {
    private String usernameAttributeName;
    private DistinguishedName userDnBase;
    private LdapTemplate template;

    private String groupBase="cn=groups";
    private String groupRoleName="cn";
    private String rolePrefix = "ROLE_";

    private ContextMapper mapper;

    private String[] objectClasses = new String[] {"top", "person", "organizationalPerson", "inetOrgPerson"};

    /** Map of user details properties to ldap attributes */
    private Map attributeMapping;

    public static void main(String[] args) {
        ContextSourceInitialDirContextFactory contextFactory = new ContextSourceInitialDirContextFactory("ldap://192.168.101.100:389/dc=acegisecurity,dc=com,dc=au");
        contextFactory.setManagerDn("uid=acegiman,cn=people,dc=acegisecurity,dc=com,dc=au");
        contextFactory.setManagerPassword("password");

        LdapUserDetailsManager mgr = new LdapUserDetailsManager(contextFactory);

        InetOrgPerson.Essence user = new InetOrgPerson.Essence();
        user.setUsername("jerrymouse");
        user.setSn("User");
        user.setCn("Test User");
        PasswordEncoder pwe = new LdapShaPasswordEncoder();
        user.setPassword(pwe.encodePassword("wheresthecheese", null));

        mgr.updateUser(user.createUserDetails());
    }

    public LdapUserDetailsManager(ContextSource contextSource) {
        template = new LdapTemplate(contextSource);
        userDnBase = new DistinguishedName("cn=users");
        Map defaultMapping = new HashMap();

        defaultMapping.put("username", "cn");
        defaultMapping.put("password", "userPassword");

        attributeMapping = Collections.unmodifiableMap(defaultMapping);
    }

    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException, DataAccessException {
        DistinguishedName dn = buildDn(username);

        return (UserDetails) template.lookup(dn, mapper);
    }

    public void createUser(UserDetails user) {
        template.bind(buildDn(user.getUsername()), getUserContextToBind(user), null);
    }

    public void updateUser(UserDetails user) throws UsernameNotFoundException {
        template.rebind(buildDn(user.getUsername()), getUserContextToBind(user), null);
    }

    public void deleteUser(String username) throws UsernameNotFoundException {
        DistinguishedName dn = buildDn(username);
        template.unbind(dn);
    }

    DirContextOperations getUserContextToBind(UserDetails user) {
        DirContextAdapter adapter = new DirContextAdapter();

        Map attributesToSet = new HashMap();
        attributesToSet.put("objectclass", objectClasses);

        BeanWrapperImpl userBean = new BeanWrapperImpl(user);
        Iterator properties = attributeMapping.keySet().iterator();

        while(properties.hasNext()) {
            String property = (String) properties.next();
            String attribute = (String) attributeMapping.get(property);

            List values = (List) attributesToSet.get(attribute);
            if(values == null) {
                values = new ArrayList();
                attributesToSet.put(attribute, values);
            }

            Object propertyValue = userBean.getPropertyValue(property);
            Assert.notNull(propertyValue);

            values.add(propertyValue);
        }

        Iterator attributes = attributesToSet.keySet().iterator();

        while(attributes.hasNext()) {
            String attributeName = (String) attributes.next();
            List values = (List) attributesToSet.get(attributeName);
            adapter.setAttributeValues(attributeName, values.toArray());
        }

        return adapter;
    }

    public boolean userExists(String username) {
        DistinguishedName dn = buildDn(username);

        try {
            Object obj = template.lookup(dn);
            if (obj instanceof Context) {
                LdapUtils.closeContext((Context) obj);
            }
            return true;
        } catch(EntryNotFoundException e) {
            return false;
        }
    }

    DistinguishedName buildDn(String username) {
        DistinguishedName dn = new DistinguishedName(userDnBase);

        dn.add(usernameAttributeName, username);

        return dn;
    }

    public void setGroupBase(String groupBase) {
        this.groupBase = groupBase;
    }

    public void setGroupRoleName(String groupRoleName) {
        this.groupRoleName = groupRoleName;
    }

    public void setUserDnBase(String userDnBase) {
        this.userDnBase = new DistinguishedName(userDnBase);
    }

    /**
     * Sets the mapping from property names on the UserDetails object to
     * directory attributes.
     *
     * @param attributeMapping the map, keyed by property name.
     */
    public void setAttributeMapping(Map attributeMapping) {
        Assert.notNull(attributeMapping.get("username"), "Mapping must contain an entry for 'username'");
        Assert.notNull(attributeMapping.get("password"), "Mapping must contain an entry for 'password'");
        usernameAttributeName = (String) attributeMapping.get("username");
        this.attributeMapping = Collections.unmodifiableMap(attributeMapping);
    }
}

class UserDetailsContextMapper implements ContextMapper {
    private Class type;
    private Map attributeMapping;

    public UserDetailsContextMapper(Map attributeMapping, Class userDetailsType) {
        type = userDetailsType;
        this.attributeMapping = attributeMapping;
    }

    public Object mapFromContext(Object ctx) {
        DirContextOperations dirContext = (DirContextOperations) ctx;
        DistinguishedName dn = new DistinguishedName(dirContext.getDn());

        return null;
    }
}
