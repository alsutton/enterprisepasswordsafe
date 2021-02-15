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

import javax.servlet.jsp.JspWriter;
import javax.servlet.jsp.tagext.TagSupport;
import java.io.IOException;

/**
 * Tag to check for an existing value for a text input tag. 
 */

public class TextInputTag extends TagSupport {

	/**
	 * 
	 */
	private static final long serialVersionUID = -8068573925440331854L;

	/**
	 * The type of the tag.
	 */
	private String type;
	
	/**
	 * The name of the tag.
	 */
	private String name;
	
	/**
	 * The value for the tag, overridden by any value set as a request
	 * parameter.
	 */
	private String value;
	
	/**
	 * Sets the size of the entry field.
	 */
	
	private String size;
	
	public int doEndTag() {
		try {
			JspWriter writer = pageContext.getOut();
			writer.print("<input type=\"");
			writer.print(type);
			writer.print("\" name=\"" );
			writer.print(name);
			writer.print("\"");
			
			if( size != null ) {
				writer.print(" size=\"");
				writer.print(size);
				writer.print('\"');
			}
							

			String outputValue = pageContext.getRequest().getParameter(name);
			if( outputValue == null
			||	outputValue.length() == 0 ) {
				outputValue = value;
			}			
			
			if( outputValue != null 
			&& outputValue.length() > 0 ) {
				writer.print(" value=\"");
				outputValue = outputValue.replaceAll("&", "&amp;");
				outputValue = outputValue.replaceAll("\"", "&quot;");
				writer.print(outputValue);
				writer.print('\"');
			}
			
			writer.println(" />");
		} catch(IOException ioe) {
			// Ignore the IO exception.
		}
		
		return EVAL_PAGE;
	}

	public void setName(String name) {
		this.name = name;
	}

	public void setType(String type) {
		this.type = type;
	}

	public void setValue(String newValue) {
		value = newValue;
	}
	
	public void setValue(int newValue) {
		value = Integer.toString(newValue);
	}
	
	public void setSize(String newSize) {
		size = newSize;
	}
	
	public void setSize(int newSize) {
		size = Integer.toString(newSize);
	}
	
}
