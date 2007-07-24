package org.acegisecurity.providers.ldap.authenticator;

import org.acegisecurity.ldap.InitialDirContextFactory;
import org.acegisecurity.ldap.DefaultInitialDirContextFactory;
import org.acegisecurity.ldap.ppolicy.PasswordExpiredException;
import org.acegisecurity.ldap.ppolicy.AccountLockedException;
import org.acegisecurity.ldap.ppolicy.PasswordPolicyException;
import org.acegisecurity.ldap.ppolicy.PasswordInHistoryException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.regex.Pattern;
import java.util.regex.Matcher;


/**
 * @author Luke
 * @version $Id$
 */
public class OracleIDBindAuthenticator extends BindAuthenticator {
    //~ Static fields/initializers =====================================================================================

    private static final Log logger = LogFactory.getLog(OracleIDBindAuthenticator.class);

    private static final Pattern oidErrorMsgPattern = Pattern.compile("^\\[LDAP: error code ([0-9]+) - .*:([0-9]{4}):.*");

    //~ Constructors ===================================================================================================

    protected OracleIDBindAuthenticator(InitialDirContextFactory initialDirContextFactory) {
        super(initialDirContextFactory);
    }

/**
    9000 GSL_PWDEXPIRED_EXCP Your Password has expired. Please contact the Administrator to change your password.
    9001 GSL_ACCOUNTLOCKED_EXCP Your account is locked. Please contact the Administrator.
    9002 GSL_EXPIREWARNING_EXCP Your Password will expire in pwdexpirewarning seconds. Please change your password now.
    9003 GSL_PWDMINLENGTH_EXCP Your Password must be at least pwdminlength characters long.
    9004 GSL_PWDNUMERIC_EXCP Your Password must contain at least orclpwdalphanumeric numeric characters.
    9005 GSL_PWDNULL_EXCP Your Password cannot be a Null Password.
    9006 GSL_PWDINHISTORY_EXCP Your New Password cannot be the same as your Old Password.
    9007 GSL_PWDILLEGALVALUE_EXCP Your Password cannot be the same as your orclpwdillegalvalues.
    9008 GSL_GRACELOGIN_EXCP Your Password has expired. You have pwdgraceloginlimit Grace logins left.
    9050 GSL_ACCTDISABLED_EXCP Your Account has been disabled. Please contact the administrator.
*/
    protected void handleBindException(String userDn, String username, Throwable exception) {
        int errorCode = parseOracleErrorCode(exception.getMessage());

        if (errorCode > 0) {
            switch (errorCode) {
                case 9000:
                    throw new PasswordExpiredException("Password has expired. Please contact an administrator.");
                case 9001:
                    throw new AccountLockedException("Account is locked. Please contact an administrator.");
//                case 9006:
//                    throw new PasswordInHistoryException("Password must not match previous password");
            }
            throw new PasswordPolicyException("OID exception: " + exception.getMessage());
        }

       // Just debug log the exception
        super.handleBindException(userDn, username, exception);
    }

    /**
     * Attempts to parse the error code from the exception message returned by OID.
     */
    private int parseOracleErrorCode(String msg) {
        Matcher matcher = oidErrorMsgPattern.matcher(msg);

        if (matcher.matches()) {
            String code = matcher.group(2);

            return Integer.parseInt(code);
        }

        return -1;
    }
}
