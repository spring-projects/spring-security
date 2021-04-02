package sample;

import org.junit.*;

public class DependencyTest {
	@Test
	public void findsDependencyOnClasspath() {
		new Dependency();
	}
}