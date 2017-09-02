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

/**
 * 
 */
package com.enterprisepasswordsafe.ui.web.jsptags;

import com.enterprisepasswordsafe.ui.web.utils.DateFormatter;

import java.io.IOException;
import java.util.Calendar;

import javax.servlet.jsp.tagext.TagSupport;


/**
 * Tag to check for an existing value for a text input tag. 
 */

public class DateInputTag extends TagSupport {

	/**
	 * 
	 */
	private static final long serialVersionUID = -7722054896784049645L;

	/**
	 * The name of the tag.
	 */
	private String prefix;
	
	/**
	 * The value for the date, overridden by any value set as a request
	 * parameter.
	 */
	private String date = null;
	
	/**
	 * The number of years into the past to display.
	 */
	
	private int yearsInPast = 0;
	
	public int doEndTag() {
		try {
			String day;
			String month;
			String year;

			if( date == null ) {
				day = (String)pageContext.getRequest().getAttribute(prefix+"_day");
				month = (String)pageContext.getRequest().getAttribute(prefix+"_month");
				year = (String)pageContext.getRequest().getAttribute(prefix+"_year");
			} else {
				day = date.substring(6,8);
				month = date.substring(4, 6); 
				year = date.substring(0, 4);			
			}
			
			String dayParameter = prefix+"_day";
	        String currentSetting = 
	        	(String) pageContext.getRequest().getParameter(dayParameter);
	        if( currentSetting == null || currentSetting.length() == 0 ) {
	        	currentSetting = day;
	        }	        
	        if( currentSetting != null && currentSetting.length() > 0 ) {
	        	displayList(dayParameter, 1, 31, currentSetting);
	        } else {
	        	displayList(dayParameter, 1, 31);	        	
	        }

	        String monthParameter = prefix+"_month";
	        currentSetting = (String) pageContext.getRequest().getParameter(monthParameter);
	        if( currentSetting == null || currentSetting.length() == 0 ) {
	        	currentSetting = month;
	        }	        
	        if( currentSetting != null && currentSetting.length() > 0 ) {
	        	displayMonthList(monthParameter, currentSetting);
	        } else {
	        	displayMonthList(monthParameter);	        	
	        }

	        Calendar cal = Calendar.getInstance();
	        int currentYear = cal.get(Calendar.YEAR);	        
	        String yearParameter = prefix+"_year";
	        currentSetting = (String) pageContext.getRequest().getParameter(yearParameter);
	        if( currentSetting == null || currentSetting.length() == 0 ) {
	        	currentSetting = year;
	        }	        
	        if( currentSetting != null && currentSetting.length() > 0  ) {
	        	displayList(yearParameter, currentYear-yearsInPast, currentYear+10, currentSetting);
	        } else {
	        	displayList(yearParameter, currentYear-yearsInPast, currentYear+10 );	        	
	        }
	        
		} catch(IOException ioe) {
			// Ignore the IO exception.
		}
		
		return EVAL_PAGE;
	}

	/**
	 * Output a select list with a specific value set.
	 * 
	 * @param name The name for the select list.
	 * @param start The start of the list values.
	 * @param end The end of the list value.
	 */
	
	private void displayList( String name, int start, int end ) 
		throws IOException {
		pageContext.getOut().print("<select name=\"");
		pageContext.getOut().print(name);
		pageContext.getOut().print("\">");
		for( int i = start ; i <= end ; i++ ) {
			pageContext.getOut().print("<option>");
			if( i < 10 ) {
				pageContext.getOut().print('0');
			}
			pageContext.getOut().print(i);
			pageContext.getOut().print("</option>");
		}
		pageContext.getOut().print("</select>");		
	}
	
	/**
	 * Output a select list with a specific value set.
	 * 
	 * @param name The name for the select list.
	 * @param start The start of the list values.
	 * @param end The end of the list value.
	 * @param selected The default selected value.
	 */
	
	private void displayList( String name, int start, int end, String selected ) 
		throws IOException {
		int selectedInt = Integer.parseInt(selected);
		
		pageContext.getOut().print("<select name=\"");
		pageContext.getOut().print(name);
		pageContext.getOut().print("\">");
		for( int i = start ; i <= end ; i++ ) {
			pageContext.getOut().print("<option");
			if(i == selectedInt ) {
				pageContext.getOut().print(" selected");
			}
			pageContext.getOut().print(">");
			if( i < 10 ) {
				pageContext.getOut().print('0');
			}
			pageContext.getOut().print(i);
			pageContext.getOut().print("</option>");
		}
		pageContext.getOut().print("</select>");		
	}
	
	/**
	 * Output a months list.
	 * 
	 * @param name The name for the select list.
	 */
	
	private void displayMonthList( String name ) 
		throws IOException {
		pageContext.getOut().print("<select name=\"");
		pageContext.getOut().print(name);
		pageContext.getOut().print("\">");
		for( int i = 1 ; i <= 12 ; i++ ) {
			pageContext.getOut().print("<option value=\"");
			if( i < 10 ) {
				pageContext.getOut().print('0');
			}
			pageContext.getOut().print(i);
			pageContext.getOut().print("\">");
			pageContext.getOut().print(DateFormatter.MONTHS[i-1]);
			pageContext.getOut().print("</option>");
		}
		pageContext.getOut().print("</select>");		
	}
	
	/**
	 * Output a select list with a specific value set.
	 * 
	 * @param name The name for the select list.
	 * @param start The start of the list values.
	 * @param end The end of the list value.
	 * @param selected The default selected value.
	 */
	
	private void displayMonthList( String name, String selected ) 
		throws IOException {
		int selectedInt = Integer.parseInt(selected);
		
		pageContext.getOut().print("<select name=\"");
		pageContext.getOut().print(name);
		pageContext.getOut().print("\">");
		for( int i = 1 ; i <= 12 ; i++ ) {
			pageContext.getOut().print("<option value=\"");
			if( i < 10 ) {
				pageContext.getOut().print('0');
			}
			pageContext.getOut().print(i);
			pageContext.getOut().print('\"');
			if( i == selectedInt ) {
				pageContext.getOut().print(" selected");
			}
			pageContext.getOut().print(">");
			pageContext.getOut().print(DateFormatter.MONTHS[i-1]);
			pageContext.getOut().print("</option>");
		}
		pageContext.getOut().print("</select>");		
	}

	/**
	 * The prefix for the _day _month and _year parameters.
	 * 
	 * @param newPrefix The prefix to use.
	 */
	public void setPrefix(String newPrefix) {
		prefix = newPrefix;
	}

	/**
	 * The default date.
	 * 
	 * @param newDate
	 */
	public void setDate(String newDate) {
		date = newDate;
	}

	/**
	 * The number of years into the past to display.
	 * 
	 * @param yearsPast The number of years into the past to display.
	 */
	public void setYearsInPast(String yearsPast) {
		yearsInPast = Integer.parseInt(yearsPast);
	}
}
