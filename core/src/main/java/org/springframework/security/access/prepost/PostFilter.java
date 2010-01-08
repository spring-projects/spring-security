package org.springframework.security.access.prepost;

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
 * @since 3.0
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
@Inherited
@Documented
public @interface PostFilter {
    /**
     * @return the Spring-EL expression to be evaluated after invoking the protected method
     */
    public String value();
}
