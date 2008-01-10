package org.springframework.security.annotation;

import org.springframework.security.SecurityConfig;
import org.springframework.metadata.Attributes;
import org.springframework.core.annotation.AnnotationUtils;

import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.lang.reflect.Method;
import java.lang.reflect.Field;
import java.lang.annotation.Annotation;

/**
 * Java 5 Annotation <code>Attributes</code> metadata implementation used for secure method interception.
 * <p>
 * This <code>Attributes</code> implementation will return security configuration for classes described using the
 * <code>RolesAllowed</code> Java JEE 5 annotation.
 * <p>
 * The <code>SecurityAnnotationAttributes</code> implementation can be used to configure a
 * <code>MethodDefinitionAttributes</code> and  <code>MethodSecurityInterceptor</code> bean definition.
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
     * Get the <code>RolesAllowed</code> attributes for a given target method.
     *
     * @param method The target method
     * @return Collection of <code>SecurityConfig</code>
     * @see Attributes#getAttributes
     */
    public Collection<SecurityConfig> getAttributes(Method method) {
    	Annotation[] annotations = AnnotationUtils.getAnnotations(method);
        Collection<SecurityConfig> attributes = populateSecurityConfigWithRolesAllowed(annotations);
        // if there is no RolesAllowed defined on the Method then we will use the one defined on the class
        // level , according to JSR 250
        if (attributes.size()==0 && !method.isAnnotationPresent(PermitAll.class)) {
        	attributes = populateSecurityConfigWithRolesAllowed(method.getDeclaringClass().getDeclaredAnnotations());
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
