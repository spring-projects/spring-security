package sample;

import org.junit.Test;
import org.springframework.core.Ordered;

public class TheTest {
	@Test
	public void compilesAndRuns() {
		Ordered ordered = new Ordered() {
			@Override
			public int getOrder() {
				return 0;
			}
		};
	}
}