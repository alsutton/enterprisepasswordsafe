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

import javax.servlet.jsp.tagext.TagSupport;
import java.io.IOException;
import java.util.Iterator;

/**
 * Tag to check for an existing value for a text input tag. 
 */

public class IteratedSelectListTag extends TagSupport {

	/**
	 * 
	 */
	private static final long serialVersionUID = 5415492231549139936L;

	/**
	 * The type of the tag.
	 */
	private Iterator<Object> iter;
	
	/**
	 * The name of the tag.
	 */
	String name;

	/**
	 * The default value for the tag
	 */
	
	String value;
	
	public int doEndTag() {
		try {			
			pageContext.getOut().print("<select name=\"" );
			pageContext.getOut().print(name);
			pageContext.getOut().print("\">");
			
			String selectedValue = pageContext.getRequest().getParameter(name);
			if( selectedValue == null
			||	selectedValue.length() == 0 ) {
				selectedValue = value;
			}
			
			if( selectedValue == null
			||	selectedValue.length() == 0 ) {
				while( iter.hasNext() ) {
					pageContext.getOut().print("<option>");
					pageContext.getOut().print(encode(iter.next().toString()));
					pageContext.getOut().println("</option>");					
				}
			} else {
				while( iter.hasNext() ) {
					pageContext.getOut().print("<option");
					String thisValue = iter.next().toString();
					if( thisValue.equals(selectedValue) ) {
						pageContext.getOut().print(" selected");
					}
					pageContext.getOut().print('>');
					pageContext.getOut().print(encode(thisValue));
					pageContext.getOut().println("</option>");					
				}				
			}
			
			pageContext.getOut().println("</select>");
		} catch(IOException ioe) {
			// Ignore the IO exception.
		}
		
		return EVAL_PAGE;
	}

	public void setName(String name) {
		this.name = name;
	}

	public void setIterator(Iterator<Object> iter) {
		this.iter = iter;
	}

	public void setValue(String value) {
		this.value = value;
	}
	
    /**
     * Encodes a string for HTML display.
     *
     * @param data The data to encode.
     *
     * @return The encoded data.
     */

    public static String encode(final String data) {
        int stringLength = data.length();
        StringBuilder buffer = new StringBuilder(stringLength);
        boolean lastWasNewline = false;
        for (int i = 0; i < stringLength; i++) {
            char c = data.charAt(i);
            if (c == '\n' || c == '\r') {
                if (!lastWasNewline) {
                    buffer.append("<br/>");
                    lastWasNewline = true;
                } else {
                    lastWasNewline = false;
                }
            } else if ( c == '<' ) {
            	buffer.append("&lt;");
            } else if ( c == '>' ) {
            	buffer.append("&gt;");            	            	
            } else if ( c == '&' ) {
            	buffer.append("&amp;");            	            	
            } else {
                buffer.append(c);
                lastWasNewline = false;
            }
        }

        return buffer.toString();
    }
}
