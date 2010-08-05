package org.springframework.security.ldap.ppolicy;


/**
 * Defines status codes for use with <tt>PasswordPolicyException</tt>, with error codes (for message source lookup) and default
 * messages.
 *
 * <pre>
 *    PasswordPolicyResponseValue ::= SEQUENCE {
 *        warning [0] CHOICE {
 *           timeBeforeExpiration [0] INTEGER (0 .. maxInt),
 *           graceAuthNsRemaining [1] INTEGER (0 .. maxInt)
 *        } OPTIONAL,
 *        error   [1] ENUMERATED {
 *           passwordExpired             (0),     accountLocked               (1),
 *           changeAfterReset            (2),     passwordModNotAllowed       (3),
 *           mustSupplyOldPassword       (4),     insufficientPasswordQuality (5),
 *           passwordTooShort            (6),     passwordTooYoung            (7),
 *           passwordInHistory           (8)
 *        } OPTIONAL
 *    }
 *</pre>
 *
 * @author Luke Taylor
 * @since 3.0
 */
public enum PasswordPolicyErrorStatus {
    PASSWORD_EXPIRED                ("ppolicy.expired", "Your password has expired"),
    ACCOUNT_LOCKED                  ("ppolicy.locked", "Account is locked"),
    CHANGE_AFTER_RESET              ("ppolicy.change.after.reset", "Your password must be changed after being reset"),
    PASSWORD_MOD_NOT_ALLOWED        ("ppolicy.mod.not.allowed", "Password cannot be changed"),
    MUST_SUPPLY_OLD_PASSWORD        ("ppolicy.must.supply.old.password",  "The old password must be supplied"),
    INSUFFICIENT_PASSWORD_QUALITY   ("ppolicy.insufficient.password.quality", "The supplied password is of insufficient quality"),
    PASSWORD_TOO_SHORT              ("ppolicy.password.too.short", "The supplied password is too short"),
    PASSWORD_TOO_YOUNG              ("ppolicy.password.too.young", "Your password was changed too recently to be changed again"),
    PASSWORD_IN_HISTORY             ("ppolicy.password.in.history", "The supplied password has already been used");

    private final String errorCode;
    private final String defaultMessage;

    private PasswordPolicyErrorStatus(String errorCode, String defaultMessage) {
        this.errorCode = errorCode;
        this.defaultMessage = defaultMessage;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public String getDefaultMessage() {
        return defaultMessage;
    }
}
