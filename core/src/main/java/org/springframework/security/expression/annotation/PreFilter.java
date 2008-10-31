package org.springframework.security.expression.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Annotation for specifying a method filtering expression which will be evaluated before a method has been invoked.
 * The name of the argument to be filtered is specified using the <tt>filterTarget</tt> attribute. This must be a
 * Java Collection implementation which supports the {@link java.util.Collection#remove(Object) remove} method.
 * Pre-filtering isn't supported on array types and will fail if the value of named filter target argument is null
 * at runtime.
 * <p>
 * For methods which have a single argument which is a collection type, this argument will be used as the filter
 * target.
 * <p>
 * The annotation value contains the expression which will be evaluated for each element in the collection. If the
 * expression evaluates to false, the element will be removed. The reserved name "filterObject" can be used within the
 * expression to refer to the current object which is being evaluated.
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
     * @return the name of the parameter which should be filtered (must be a non-null collection instance)
     * If the method contains a single collection argument, then this attribute can be omitted.
     */
    public String filterTarget() default "";
}
