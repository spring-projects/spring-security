import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.providers.UsernamePasswordAuthenticationToken;
import org.springframework.test.AbstractTransactionalDataSourceSpringContextTests;

import sample.dms.AbstractElement;
import sample.dms.Directory;
import sample.dms.DocumentDao;

/**
 * Basic integration test for DMS sample.
 *
 * @author Ben Alex
 * @version $Id$
 *
 */
public class DmsIntegrationTests extends AbstractTransactionalDataSourceSpringContextTests {
    protected DocumentDao documentDao;

    protected String[] getConfigLocations() {
        return new String[] {"classpath:applicationContext-dms-shared.xml", "classpath:applicationContext-dms-insecure.xml"};
    }

	protected void onTearDown() throws Exception {
        SecurityContextHolder.clearContext();
	}

    public void setDocumentDao(DocumentDao documentDao) {
        this.documentDao = documentDao;
    }

    public void testBasePopulation() {
        assertEquals(9, jdbcTemplate.queryForInt("select count(id) from DIRECTORY"));
        assertEquals(90, jdbcTemplate.queryForInt("select count(id) from FILE"));
        assertEquals(3, documentDao.findElements(Directory.ROOT_DIRECTORY).length);
    }

    public void testMarissaRetrieval() {
        process("rod", "koala", false);
    }

    public void testScottRetrieval() {
        process("scott", "wombat", false);
    }

    public void testDianneRetrieval() {
        process("dianne", "emu", false);
    }

    protected void process(String username, String password, boolean shouldBeFiltered) {
        SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(username, password));
        System.out.println("------ Test for username: " + username + " ------");
        AbstractElement[] rootElements = documentDao.findElements(Directory.ROOT_DIRECTORY);
        assertEquals(3, rootElements.length);
        Directory homeDir = null;
        Directory nonHomeDir = null;
        for (int i = 0; i < rootElements.length; i++) {
            if (rootElements[i].getName().equals(username)) {
                homeDir = (Directory) rootElements[i];
            } else {
                nonHomeDir = (Directory) rootElements[i];
            }
        }
        System.out.println("Home directory......: " + homeDir.getFullName());
        System.out.println("Non-home directory..: " + nonHomeDir.getFullName());

        AbstractElement[] homeElements = documentDao.findElements(homeDir);
        assertEquals(12, homeElements.length); // confidential and shared directories, plus 10 files

        AbstractElement[] nonHomeElements = documentDao.findElements(nonHomeDir);
        assertEquals(shouldBeFiltered ? 11 : 12, nonHomeElements.length); // cannot see the user's "confidential" sub-directory when filtering

        // Attempt to read the other user's confidential directory from the returned results
        // Of course, we shouldn't find a "confidential" directory in the results if we're filtering
        Directory nonHomeConfidentialDir = null;
        for (int i = 0; i < nonHomeElements.length; i++) {
            if (nonHomeElements[i].getName().equals("confidential")) {
                nonHomeConfidentialDir = (Directory) nonHomeElements[i];
            }
        }

        if (shouldBeFiltered) {
            assertNull("Found confidential directory when we should not have", nonHomeConfidentialDir);
        } else {
            System.out.println("Inaccessible dir....: " + nonHomeConfidentialDir.getFullName());
            assertEquals(10, documentDao.findElements(nonHomeConfidentialDir).length); // 10 files (no sub-directories)
        }

        SecurityContextHolder.clearContext();
    }

}
