import static org.assertj.core.api.Assertions.*;

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
		assertThat(jdbcTemplate.queryForObject("select count(id) from DIRECTORY", Integer.class)).isEqualTo(9);
		assertThat(jdbcTemplate.queryForObject("select count(id) from FILE", Integer.class)).isEqualTo(90);
		assertThat(jdbcTemplate.queryForObject("select count(id) from ACL_SID", Integer.class)).isEqualTo(4); // 3 users + 1 role
		assertThat(jdbcTemplate.queryForObject("select count(id) from ACL_CLASS", Integer.class)).isEqualTo(2); // Directory
																												// and
																												// File
		assertThat(jdbcTemplate.queryForObject("select count(id) from ACL_OBJECT_IDENTITY", Integer.class))
				.isEqualTo(100);
		assertThat(jdbcTemplate.queryForObject("select count(id) from ACL_ENTRY", Integer.class)).isEqualTo(115);
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
