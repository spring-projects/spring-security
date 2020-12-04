package org.springframework.security.ldap.jackson2;

import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.ldap.userdetails.InetOrgPerson;
import org.springframework.security.ldap.userdetails.LdapAuthority;
import org.springframework.security.ldap.userdetails.LdapUserDetailsImpl;
import org.springframework.security.ldap.userdetails.Person;

import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.module.SimpleModule;

/**
 * Jackson module for spring-security-ldap. This module register {@link LdapAuthorityMixin},
 * {@link LdapUserDetailsImplMixin}, {@link PersonMixin}, {@link InetOrgPersonMixin}.
 * If no default typing enabled by default then it'll enable it because typing info is needed to properly
 * serialize/deserialize objects. In order to use this module just add this module into your ObjectMapper configuration.
 *
 * <pre>
 *     ObjectMapper mapper = new ObjectMapper();
 *     mapper.registerModule(new LdapJackson2Module());
 * </pre>
 * <b>Note: use {@link SecurityJackson2Modules#getModules(ClassLoader)} to get list of all security modules.</b>
 *
 * @see SecurityJackson2Modules
 */
public class LdapJackson2Module extends SimpleModule {

    public LdapJackson2Module() {
        super(LdapJackson2Module.class.getName(), new Version(1, 0, 0, null, null, null));
    }

    @Override
    public void setupModule(SetupContext context) {
        SecurityJackson2Modules.enableDefaultTyping(context.getOwner());
        context.setMixInAnnotations(LdapAuthority.class, LdapAuthorityMixin.class);
        context.setMixInAnnotations(LdapUserDetailsImpl.class, LdapUserDetailsImplMixin.class);
        context.setMixInAnnotations(Person.class, PersonMixin.class);
        context.setMixInAnnotations(InetOrgPerson.class, InetOrgPersonMixin.class);
    }

}
