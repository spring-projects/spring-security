package org.springframework.security.ldap.ppolicy;

/**
 * Generic exception raised by the ppolicy package.
 * <p>
 * The <tt>status</tt> property should be checked for more detail on the cause of the exception.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class PasswordPolicyException extends RuntimeException {
   private PasswordPolicyErrorStatus status;

   public PasswordPolicyException(PasswordPolicyErrorStatus status) {
       super(status.getDefaultMessage());
       this.status = status;
   }

   public PasswordPolicyErrorStatus getStatus() {
       return status;
   }
}
