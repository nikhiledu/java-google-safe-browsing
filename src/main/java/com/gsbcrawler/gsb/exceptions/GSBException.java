package com.gsbcrawler.gsb.exceptions;

/**
 * GSBException
 * Generic GSB Exception that may be thrown by any number of classes
 *
 * <h4>Copyright and License</h4>
 * This code is copyright (c) Buildabrand Ltd, 2011 except where
 * otherwise stated. It is released as
 * open-source under the Creative Commons NC-SA license. See
 * <a href="http://creativecommons.org/licenses/by-nc-sa/2.5/">http://creativecommons.org/licenses/by-nc-sa/2.5/</a>
 * for license details. This code comes with no warranty or support.
 *
 * @author Dave Shanley <dave@buildabrand.com>
 */
public class GSBException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 849397795677717752L;

	public GSBException() {
		super();
	}

	public GSBException(String arg0) {
		super(arg0);
	}

}
