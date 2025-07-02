package org.springframework.security.core.annotation;

/**
 * Provides a mechanism for providing custom values from enum types used in security
 * meta-annotation expressions. For example:
 *
 * <pre>
 * enum Permission implements ExpressionTemplateValueProvider {
 *   READ,
 *   WRITE;
 *
 *   &#64;Override
 *   public String getExpressionTemplateValue() {
 *     return switch (this) {
 *       case READ -> "user.permission-read";
 *       case WRITE -> "user.permission-write";
 *     }
 *   }
 *
 * }
 * </pre>
 *
 * @since 6.5
 * @author Mike Heath
 */
public interface ExpressionTemplateValueProvider {

	/**
	 * Returns the value to be used in an expression template.
	 *
	 * @return the value to be used in an expression template
	 */
	String getExpressionTemplateValue();

}
