import static org.assertj.core.api.Assertions.*;

import org.junit.After;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.AbstractTransactionalJUnit4SpringContextTests;

import sample.dms.AbstractElement;
import sample.dms.Directory;
import sample.dms.DocumentDao;

/**
 * Basic integration test for DMS sample.
 *
 * @author Ben Alex
 *
 */
@ContextConfiguration(locations = { "classpath:applicationContext-dms-shared.xml",
		"classpath:applicationContext-dms-insecure.xml" })
public class DmsIntegrationTests extends AbstractTransactionalJUnit4SpringContextTests {

	@Autowired
	protected JdbcTemplate jdbcTemplate;

	@Autowired
	protected DocumentDao documentDao;

	@After
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	public void setDocumentDao(DocumentDao documentDao) {
		this.documentDao = documentDao;
	}

	@Test
	public void testBasePopulation() {
		assertThat(jdbcTemplate.queryForObject("select count(id) from DIRECTORY", Integer.class)).isEqualTo(9);
		assertThat((int) jdbcTemplate.queryForObject("select count(id) from FILE", Integer.class)).isEqualTo(90);
		assertThat(documentDao.findElements(Directory.ROOT_DIRECTORY).length).isEqualTo(3);
	}

	@Test
	public void testMarissaRetrieval() {
		process("rod", "koala", false);
	}

	@Test
	public void testScottRetrieval() {
		process("scott", "wombat", false);
	}

	@Test
	public void testDianneRetrieval() {
		process("dianne", "emu", false);
	}

	protected void process(String username, String password, boolean shouldBeFiltered) {
		SecurityContextHolder.getContext().setAuthentication(
				new UsernamePasswordAuthenticationToken(username, password));
		System.out.println("------ Test for username: " + username + " ------");
		AbstractElement[] rootElements = documentDao
				.findElements(Directory.ROOT_DIRECTORY);
		assertThat(rootElements.length).isEqualTo(3);
		Directory homeDir = null;
		Directory nonHomeDir = null;
		for (int i = 0; i < rootElements.length; i++) {
			if (rootElements[i].getName().equals(username)) {
				homeDir = (Directory) rootElements[i];
			}
			else {
				nonHomeDir = (Directory) rootElements[i];
			}
		}
		System.out.println("Home directory......: " + homeDir.getFullName());
		System.out.println("Non-home directory..: " + nonHomeDir.getFullName());

		AbstractElement[] homeElements = documentDao.findElements(homeDir);
		assertThat(homeElements.length).isEqualTo(12); // confidential and shared directories,
												// plus 10 files

		AbstractElement[] nonHomeElements = documentDao.findElements(nonHomeDir);
		assertThat(nonHomeElements.length).isEqualTo(shouldBeFiltered ? 11 : 12); // cannot see
																			// the user's
																			// "confidential"
																			// sub-directory
																			// when
																			// filtering

		// Attempt to read the other user's confidential directory from the returned
		// results
		// Of course, we shouldn't find a "confidential" directory in the results if we're
		// filtering
		Directory nonHomeConfidentialDir = null;
		for (int i = 0; i < nonHomeElements.length; i++) {
			if (nonHomeElements[i].getName().equals("confidential")) {
				nonHomeConfidentialDir = (Directory) nonHomeElements[i];
			}
		}

		if (shouldBeFiltered) {
			assertThat(nonHomeConfidentialDir).withFailMessage("Found confidential directory when we should not have").isNull();
		}
		else {
			System.out.println("Inaccessible dir....: "
					+ nonHomeConfidentialDir.getFullName());
			assertThat(documentDao.findElements(nonHomeConfidentialDir).length).isEqualTo(10); // 10
																						// files
																						// (no
																						// sub-directories)
		}

		SecurityContextHolder.clearContext();
	}

}
