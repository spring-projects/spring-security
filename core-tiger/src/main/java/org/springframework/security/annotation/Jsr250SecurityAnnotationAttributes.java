package org.springframework.security.annotation;

import org.springframework.security.SecurityConfig;
import org.springframework.metadata.Attributes;
import org.springframework.core.annotation.AnnotationUtils;

import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.annotation.security.DenyAll;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.ArrayList;
import java.lang.reflect.Method;
import java.lang.reflect.Field;
import java.lang.annotation.Annotation;

/**
 * Java 5 Annotation {@link Attributes} metadata implementation used for secure method interception using
 * the security anotations defined in JSR-250.
 * <p>
 * This <code>Attributes</code> implementation will return security configuration for classes described using the
 * Java JEE 5 annotations (<em>DenyAll</em>, <em>PermitAll</em> and <em>RolesAllowed</em>).
 * <p>
 *
 * @author Mark St.Godard
 * @author Usama Rashwan
 * @author Luke Taylor
 * @since 2.0
 *
 * @see javax.annotation.security.RolesAllowed
 */

public class Jsr250SecurityAnnotationAttributes implements Attributes {
    
    //~ Methods ========================================================================================================

    /**
     * Get the <code>RolesAllowed</code> attributes for a given target class.
     * This method will return an empty Collection because the call to getAttributes(method) will override the class
     * annotation.
     *
     * @param target The target Object
     * @return Empty Collection of <code>SecurityConfig</code>
     *
     * @see Attributes#getAttributes
     */
    public Collection<SecurityConfig> getAttributes(Class target) {
        return new HashSet<SecurityConfig>();
    }

    /**
     * Get the attributes for a given target method, acording to JSR-250 precedence rules.
     *
     * @param method The target method
     * @return Collection of <code>SecurityConfig</code>
     * @see Attributes#getAttributes
     */
    public Collection<SecurityConfig> getAttributes(Method method) {
        ArrayList<SecurityConfig> attributes = new ArrayList<SecurityConfig>();

        if (AnnotationUtils.getAnnotation(method, DenyAll.class) != null) {
            attributes.add(Jsr250SecurityConfig.DENY_ALL_ATTRIBUTE);

            return attributes;
        }

        if (AnnotationUtils.getAnnotation(method, PermitAll.class) != null) {
            attributes.add(Jsr250SecurityConfig.PERMIT_ALL_ATTRIBUTE);

            return attributes;
        }

        RolesAllowed rolesAllowed = AnnotationUtils.getAnnotation(method, RolesAllowed.class);
        
        if (rolesAllowed != null) {
            for (String role : rolesAllowed.value()) {
                attributes.add(new Jsr250SecurityConfig(role));
            }

            return attributes;
        }

        // Now check the class-level attributes:
        if (method.getDeclaringClass().getAnnotation(DenyAll.class) != null) {
            attributes.add(Jsr250SecurityConfig.DENY_ALL_ATTRIBUTE);

            return attributes;
        }

        if (method.getDeclaringClass().getAnnotation(PermitAll.class) != null) {
            attributes.add(Jsr250SecurityConfig.PERMIT_ALL_ATTRIBUTE);

            return attributes;
        }

        rolesAllowed = method.getDeclaringClass().getAnnotation(RolesAllowed.class);

        if (rolesAllowed != null) {
            for (String role : rolesAllowed.value()) {
                attributes.add(new Jsr250SecurityConfig(role));
            }
        }

        return attributes;
    }

    protected Collection<SecurityConfig> populateSecurityConfigWithRolesAllowed (Annotation[] annotations) {
        Set<SecurityConfig> attributes = new HashSet<SecurityConfig>();
    	for (Annotation annotation : annotations) {
            // check for RolesAllowed annotations
            if (annotation instanceof RolesAllowed) {
            	RolesAllowed attr = (RolesAllowed) annotation;

                for (String auth : attr.value()) {
                    attributes.add(new SecurityConfig(auth));
                }

                break;
            }
        }
    	return attributes;
    }

    public Collection getAttributes(Class clazz, Class filter) {
        throw new UnsupportedOperationException();
    }

    public Collection getAttributes(Method method, Class clazz) {
        throw new UnsupportedOperationException();
    }

    public Collection getAttributes(Field field) {
        throw new UnsupportedOperationException();
    }

    public Collection getAttributes(Field field, Class clazz) {
        throw new UnsupportedOperationException();
    }
}
