package org.springframework.security.expression.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation for specifying a method filtering expression which will be evaluated after a method has been invoked.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.5
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface PreFilter {
    /**
     * @return the Spring-EL expression to be evaluated before invoking the protected method
     */
    public String value();

    /**
     * @return the name of the parameter which should be filtered (must be an array or collection)
     */
    public String filterTarget();
}
