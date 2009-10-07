import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.springframework.test.context.ContextConfiguration;



/**
 * Basic integration test for DMS sample when security has been added.
 *
 * @author Ben Alex
 * @version $Id$
 *
 */
@ContextConfiguration(locations={"classpath:applicationContext-dms-shared.xml", "classpath:applicationContext-dms-secure.xml"})
public class SecureDmsIntegrationTests extends DmsIntegrationTests {

//    @Autowired
//    private AclService aclService;

    @Test
    public void testBasePopulation() {
        assertEquals(9, jdbcTemplate.queryForInt("select count(id) from DIRECTORY"));
        assertEquals(90, jdbcTemplate.queryForInt("select count(id) from FILE"));
        assertEquals(4, jdbcTemplate.queryForInt("select count(id) from ACL_SID")); // 3 users + 1 role
        assertEquals(2, jdbcTemplate.queryForInt("select count(id) from ACL_CLASS")); // Directory and File
        assertEquals(100, jdbcTemplate.queryForInt("select count(id) from ACL_OBJECT_IDENTITY"));
        assertEquals(115, jdbcTemplate.queryForInt("select count(id) from ACL_ENTRY"));
    }
    /*
    public void testItOut() {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken("rod", "password", new GrantedAuthority[] {new GrantedAuthorityImpl("ROLE_SUPERVISOR")}));


        AbstractElement[] elements = documentDao.findElements(Directory.ROOT_DIRECTORY);
        ObjectIdentity oid = new ObjectIdentityImpl(elements[0]);
        //ObjectIdentity oid = new ObjectIdentityImpl(Directory.class, new Long(3));
        Acl acl = aclService.readAclById(oid);
        System.out.println(acl);

    }*/

    public void testMarissaRetrieval() {
        process("rod", "koala", true);
    }


    public void testScottRetrieval() {
        process("scott", "wombat", true);
    }

    public void testDianneRetrieval() {
        process("dianne", "emu", true);
    }
}
