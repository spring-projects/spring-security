package sample;

import static org.junit.Assert.*;

import org.junit.Test;

public class TheClassTest {
	TheClass theClass = new TheClass();

	@Test
	public void doStuffWhenTrueThenTrue() {
		assertTrue(theClass.doStuff(true));
	}

	@Test
	public void doStuffWhenTrueThenFalse() {
		assertFalse(theClass.doStuff(false));
	}
}