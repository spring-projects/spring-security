package net.sf.acegisecurity.providers.x509.populator;

import junit.framework.TestCase;
import net.sf.acegisecurity.providers.dao.AuthenticationDao;
import net.sf.acegisecurity.providers.dao.UsernameNotFoundException;
import net.sf.acegisecurity.providers.dao.User;
import net.sf.acegisecurity.providers.x509.X509TestUtils;
import net.sf.acegisecurity.UserDetails;
import net.sf.acegisecurity.GrantedAuthority;
import net.sf.acegisecurity.GrantedAuthorityImpl;
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
