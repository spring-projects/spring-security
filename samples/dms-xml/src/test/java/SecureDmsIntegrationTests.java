import static org.junit.Assert.assertEquals;

import org.junit.Test;
import org.springframework.test.context.ContextConfiguration;

/**
 * Basic integration test for DMS sample when security has been added.
 *
 * @author Ben Alex
 *
 */
@ContextConfiguration(locations = { "classpath:applicationContext-dms-shared.xml",
		"classpath:applicationContext-dms-secure.xml" })
public class SecureDmsIntegrationTests extends DmsIntegrationTests {

	@Test
	public void testBasePopulation() {
		assertEquals(9,
				jdbcTemplate.queryForObject("select count(id) from DIRECTORY", int.class));
		assertEquals(90,
				jdbcTemplate.queryForObject("select count(id) from FILE", int.class));
		assertEquals(4,
				jdbcTemplate.queryForObject("select count(id) from ACL_SID", int.class));	// 3
																							// users
																							// + 1
																							// role
		assertEquals(2,
				jdbcTemplate.queryForObject("select count(id) from ACL_CLASS", int.class)); // Directory
																							// and
																							// File
		assertEquals(100,
				jdbcTemplate.queryForObject("select count(id) from ACL_OBJECT_IDENTITY", int.class));
		assertEquals(115,
				jdbcTemplate.queryForObject("select count(id) from ACL_ENTRY", int.class));
	}

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
