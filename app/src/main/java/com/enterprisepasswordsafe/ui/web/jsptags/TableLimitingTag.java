/*
 * Copyright (c) 2017 Carbon Security Ltd. <opensource@carbonsecurity.co.uk>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package com.enterprisepasswordsafe.ui.web.jsptags;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.TagSupport;
import java.io.IOException;

/**
 * Tag to check for an existing value for a text input tag. 
 */

public class TableLimitingTag extends TagSupport {

	/**
	 * 
	 */
	private static final long serialVersionUID = 5036551958917690717L;

	/**
	 * The repetition cycle for the data
	 */
	private int width;
	
	/**
	 * The current index in the loop.
	 */
	
	private String counterVariable;
	
	/**
	 * Do the start tag.
	 */
	
	public int doStartTag() 
		throws JspException {
		int currentIndex = Integer.parseInt(pageContext.getAttribute(counterVariable).toString());
		if(currentIndex > 0 && currentIndex%width == 0) {
			try {
				pageContext.getOut().print("</tr><tr>");
			} catch(IOException ioe) {
				throw new JspException(ioe);
			}
			
		}
			
		return EVAL_BODY_INCLUDE;
	}

	/**
	 * Set the maximum number of columns for the table.
	 * 
	 * @param newWidth The maximum number of columns.
	 */
	public void setWidth(int newWidth) {
		width = newWidth;
	}

	/**
	 * Set the current entry number.
	 * 
	 * @param newCounterVariable The current entry number.
	 */
	public void setCounterVariable(String newCounterVariable) {
		counterVariable = newCounterVariable;
	}
	
}
