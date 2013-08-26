package javacard.framework;

/*
 * Copyright (c) 2013 Yubico AB
 * All rights reserved.
 */

public abstract class Applet {
	private boolean selecting = false;
	
    protected boolean selectingApplet() {
    	boolean state = selecting;
    	selecting = false;
    	return state;
    }
    
    public void mockSelectApplet(boolean select) {
    	selecting = select;
    }
}
