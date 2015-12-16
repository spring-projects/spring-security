import static org.assertj.core.api.Assertions.assertThat;

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
				(int) jdbcTemplate.queryForObject("select count(id) from DIRECTORY", Integer.class));
		assertEquals(90,
				(int) jdbcTemplate.queryForObject("select count(id) from FILE", Integer.class));
		assertEquals(4,
				(int) jdbcTemplate.queryForObject("select count(id) from ACL_SID", Integer.class));	// 3
																							// users
																							// + 1
																							// role
		assertEquals(2,
				(int) jdbcTemplate.queryForObject("select count(id) from ACL_CLASS", Integer.class)); // Directory
																							// and
																							// File
		assertEquals(100,
				(int) jdbcTemplate.queryForObject("select count(id) from ACL_OBJECT_IDENTITY", Integer.class));
		assertEquals(115,
				(int) jdbcTemplate.queryForObject("select count(id) from ACL_ENTRY", Integer.class));
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
