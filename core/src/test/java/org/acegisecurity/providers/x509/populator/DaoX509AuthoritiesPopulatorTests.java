package net.sf.acegisecurity.providers.x509.populator;

import junit.framework.TestCase;
import net.sf.acegisecurity.providers.dao.AuthenticationDao;
import net.sf.acegisecurity.providers.dao.UsernameNotFoundException;
import net.sf.acegisecurity.providers.dao.User;
import net.sf.acegisecurity.providers.x509.X509TestUtils;
import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
import net.sf.acegisecurity.BadCredentialsException;
import org.springframework.dao.DataAccessException;

import java.security.cert.X509Certificate;

/**
 * @author Luke Taylor
 */
public class DaoX509AuthoritiesPopulatorTests extends TestCase {
    //~ Constructors ===========================================================

    public DaoX509AuthoritiesPopulatorTests() {
        super();
    }

    public DaoX509AuthoritiesPopulatorTests(String arg0) {
        super(arg0);
    }

    //~ Methods ================================================================

    public final void setUp() throws Exception {
        super.setUp();
    }

    public void testRequiresDao() throws Exception {
        DaoX509AuthoritiesPopulator populator = new DaoX509AuthoritiesPopulator();
        try {
            populator.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch(IllegalArgumentException failed) {
            // ignored
        }
    }

    public void testInvalidRegexFails() throws Exception {
        DaoX509AuthoritiesPopulator populator = new DaoX509AuthoritiesPopulator();
        populator.setAuthenticationDao(new MockAuthenticationDaoMatchesNameOrEmail());
        populator.setSubjectDNRegex("CN=(.*?,"); // missing closing bracket on group
        try {
            populator.afterPropertiesSet();
            fail("Should have thrown IllegalArgumentException");
        } catch(IllegalArgumentException failed) {
            // ignored
        }
    }

    public void testDefaultCNPatternMatch() throws Exception{
        X509Certificate cert = X509TestUtils.buildTestCertificate();
        DaoX509AuthoritiesPopulator populator = new DaoX509AuthoritiesPopulator();

        populator.setAuthenticationDao(new MockAuthenticationDaoMatchesNameOrEmail());
        populator.afterPropertiesSet();
        populator.getUserDetails(cert);
    }

    public void testEmailPatternMatch() throws Exception{
        X509Certificate cert = X509TestUtils.buildTestCertificate();
        DaoX509AuthoritiesPopulator populator = new DaoX509AuthoritiesPopulator();

        populator.setAuthenticationDao(new MockAuthenticationDaoMatchesNameOrEmail());
        populator.setSubjectDNRegex("emailAddress=(.*?),");
        populator.afterPropertiesSet();
        populator.getUserDetails(cert);
    }

    public void testPatternWithNoGroupFails() throws Exception {
        X509Certificate cert = X509TestUtils.buildTestCertificate();
        DaoX509AuthoritiesPopulator populator = new DaoX509AuthoritiesPopulator();

        populator.setAuthenticationDao(new MockAuthenticationDaoMatchesNameOrEmail());
        populator.setSubjectDNRegex("CN=.*?,");
        populator.afterPropertiesSet();
        try {
            populator.getUserDetails(cert);
            fail("Should have thrown IllegalArgumentException for regexp without group");
        } catch (IllegalArgumentException e) {
            // ignored
        }
    }

    public void testMatchOnShoeSizeFieldInDNFails() throws Exception {
        X509Certificate cert = X509TestUtils.buildTestCertificate();
        DaoX509AuthoritiesPopulator populator = new DaoX509AuthoritiesPopulator();

        populator.setAuthenticationDao(new MockAuthenticationDaoMatchesNameOrEmail());
        populator.setSubjectDNRegex("shoeSize=(.*?),");
        populator.afterPropertiesSet();
        try {
            populator.getUserDetails(cert);
            fail("Should have thrown BadCredentialsException.");
        } catch (BadCredentialsException failed) {
            // ignored
        }
    }

    //~ Inner Classes ==========================================================
    private class MockAuthenticationDaoMatchesNameOrEmail implements AuthenticationDao {

        public UserDetails loadUserByUsername(String username)
            throws UsernameNotFoundException, DataAccessException {
            if ("Luke Taylor".equals(username) || "luke@monkeymachine".equals(username)) {
                return new User("luke", "monkey", true, true, true,
                    new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_ONE")});
            } else {
                throw new UsernameNotFoundException("Could not find: "
                    + username);
            }
        }
    }
}
