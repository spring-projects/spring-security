/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.attribute;

import junit.framework.TestCase;

import net.sf.acegisecurity.Authentication;
import net.sf.acegisecurity.ConfigAttribute;
import net.sf.acegisecurity.ConfigAttributeDefinition;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.MethodDefinitionAttributes;
import net.sf.acegisecurity.SecurityConfig;
import net.sf.acegisecurity.context.ContextHolder;
import net.sf.acegisecurity.context.SecureContextImpl;
import net.sf.acegisecurity.providers.TestingAuthenticationToken;

import org.springframework.context.support.ClassPathXmlApplicationContext;

import java.lang.reflect.Method;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;


/**
 * DOCUMENT ME!
 *
 * @author CameronBraid
 */
public class AttributesTests extends TestCase {
    //~ Instance fields ========================================================

    ClassPathXmlApplicationContext applicationContext;

    //~ Constructors ===========================================================

    /**
     *
     */
    public AttributesTests(String a) {
        super(a);
    }

    //~ Methods ================================================================

    public void testAttributesForImpl() throws Exception {
        ConfigAttributeDefinition def = getConfigAttributeDefinition(TestServiceImpl.class);
        Set set = toSet(def);
        assertTrue(set.contains(new SecurityConfig("ROLE_INTERFACE")));
        assertTrue(set.contains(new SecurityConfig("ROLE_INTERFACE_METHOD")));

        assertTrue(set.contains(new SecurityConfig("ROLE_CLASS")));
        assertTrue(set.contains(new SecurityConfig("ROLE_CLASS_METHOD")));
    }

    public void testAttributesForInterface() throws Exception {
        ConfigAttributeDefinition def = getConfigAttributeDefinition(TestService.class);
        Set set = toSet(def);
        System.out.println(set.toString());
        assertTrue(set.contains(new SecurityConfig("ROLE_INTERFACE")));
        assertTrue(set.contains(new SecurityConfig("ROLE_INTERFACE_METHOD")));
    }

    public void testInterceptionWithMockAttributesAndSecureContext()
        throws Exception {
        applicationContext = new ClassPathXmlApplicationContext(
                "/net/sf/acegisecurity/attribute/applicationContext.xml");

        TestService service = (TestService) applicationContext.getBean(
                "testService");

        SecureContextImpl context = new SecureContextImpl();
        ContextHolder.setContext(context);

        Authentication auth;

        auth = new TestingAuthenticationToken("test", "test",
                new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_CLASS"), new GrantedAuthorityImpl(
                        "ROLE_INTERFACE"), new GrantedAuthorityImpl(
                        "ROLE_CLASS_METHOD"), new GrantedAuthorityImpl(
                        "ROLE_INTERFACE_METHOD")});

        context.setAuthentication(auth);
        service.myMethod();

        auth = new TestingAuthenticationToken("test", "test",
                new GrantedAuthority[] {});
        context.setAuthentication(auth);

        try {
            service.myMethod();
            fail(
                "security interceptor should have detected insufficient permissions");
        } catch (Exception e) {}

        applicationContext.close();
        ContextHolder.setContext(null);
    }

    private ConfigAttributeDefinition getConfigAttributeDefinition(Class clazz)
        throws Exception {
        final Method method = clazz.getMethod("myMethod", null);
        MethodDefinitionAttributes source = new MethodDefinitionAttributes();
        source.setAttributes(new TestAttributes());

        ConfigAttributeDefinition config = source.getAttributes(new MockMethodInvocation() {
                    public Method getMethod() {
                        return method;
                    }
                });

        return config;
    }

    /**
     * convert a ConfigAttributeDefinition into a set of
     * <code>ConfigAttribute</code>(s)
     *
     * @param def DOCUMENT ME!
     *
     * @return
     */
    private Set toSet(ConfigAttributeDefinition def) {
        Set set = new HashSet();
        Iterator i = def.getConfigAttributes();

        while (i.hasNext()) {
            ConfigAttribute a = (ConfigAttribute) i.next();
            set.add(a);
        }

        return set;
    }
}
