/*
 * The Acegi Security System for Spring is published under the terms
 * of the Apache Software License.
 *
 * Visit http://acegisecurity.sourceforge.net for further details.
 */

package net.sf.acegisecurity.attribute;

import net.sf.acegisecurity.SecurityConfig;

import java.lang.reflect.Method;

import java.util.Arrays;
import java.util.Collection;
import java.util.List;


/**
 * DOCUMENT ME!
 *
 * @author CameronBraid
 */
public class TestAttributes extends MockAttributes {
    //~ Instance fields ========================================================

    List classAttributes = Arrays.asList(new SecurityConfig[] {new SecurityConfig(
                    "ROLE_CLASS")});
    List classMethodAttributes = Arrays.asList(new SecurityConfig[] {new SecurityConfig(
                    "ROLE_CLASS_METHOD")});
    List intrefaceAttributes = Arrays.asList(new SecurityConfig[] {new SecurityConfig(
                    "ROLE_INTERFACE")});
    List intrefaceMethodAttributes = Arrays.asList(new SecurityConfig[] {new SecurityConfig(
                    "ROLE_INTERFACE_METHOD")});

    //~ Methods ================================================================

    public Collection getAttributes(Class clazz) {
        // interface
        if (clazz.equals(TestServiceImpl.class)) {
            return classAttributes;
        }

        // class
        if (clazz.equals(TestService.class)) {
            return intrefaceAttributes;
        }

        return null;
    }

    public Collection getAttributes(Method method) {
        // interface
        if (method.getDeclaringClass().equals(TestService.class)) {
            return intrefaceMethodAttributes;
        }

        // class
        if (method.getDeclaringClass().equals(TestServiceImpl.class)) {
            return classMethodAttributes;
        }

        return null;
    }
}
