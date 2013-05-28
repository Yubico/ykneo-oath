package pkgYkneoOathTest;

import static org.junit.Assert.*;
import static org.junit.matchers.JUnitMatchers.*;

import org.junit.Test;

import pkgYkneoOath.OathObj;

public class OathObjTest {
	@Test
	public void TestCreate() {
		OathObj obj = new OathObj();
		obj.addObject();
		assertEquals(obj, OathObj.firstObject);
	}
}
