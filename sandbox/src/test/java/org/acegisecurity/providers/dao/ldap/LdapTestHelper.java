package net.sf.acegisecurity.providers.dao.ldap;

import java.io.File;

/** 
 * LdapTestHelper - used as static field in BaseLdapTestCase;
 *  responsible for global state during JUnit tests - since 
 *  JUnit reinstantiates the test class for every method.
 *
 */
public class LdapTestHelper {
	
	private File tempDirectory;
	
	/**
	 * 
	 */
	public LdapTestHelper() {
		String tmpDir = System.getProperty("java.io.tmpdir");
		File dir = new File(tmpDir);
		tempDirectory = new File(dir, "apacheds_tmp");
		if (!tempDirectory.exists()) {
			tempDirectory.mkdir();
			//tempDirectory.deleteOnExit();
		}
	}
	
	/** since file..deleteOnExit() isn't working for me, explicitly force cleanup. */
	protected void finalize() throws Throwable {
		File[] files = tempDirectory.listFiles();
		for (int i = 0; i < files.length; i++) {
			files[i].delete();
		}
		tempDirectory.delete();
		super.finalize();
	}
	

	public File getTempDirectory() {
		return tempDirectory;
	}
	
	public String getTempDirectoryPath() {
		return tempDirectory.getAbsolutePath();
	}
	
	

}
