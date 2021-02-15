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

package com.enterprisepasswordsafe.engine.scripting;

import java.io.*;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Object which implements a "waitfor" and "send" commands in a stream.
 * 
 * @author Compaq_Owner
 */

public class SimpleTerminalInteractor {

	/**
	 * The timeout for a wait script.
	 */
	
	private static final long WAIT_TIMEOUT = 60 * 1000;	// 60s
	
	/**
	 * The stdin stream from the endpoint.
	 */
	
	private final InputStream stdout;
	
	/**
	 * The stderr stream from the endpoint.
	 */
	
	private final InputStream stderr;
	
	/**
	 * The output stream to the endpoint.
	 */
	
	private final OutputStream stdin;
	
	/**
	 * Constructor. Store the reader and writer.
	 */
	
	public SimpleTerminalInteractor( InputStream theStdout, 
			InputStream theStderr, OutputStream theStdin ) {
		stdout = theStdout;
		stderr = theStderr;
		stdin = theStdin;		
	}
	
	/**
	 * Constructor. Store the reader and writer.
	 */
	
	public SimpleTerminalInteractor( InputStream theStdout, OutputStream theStdin ) {
		stdout = theStdout;
		stderr = theStdout;
		stdin = theStdin;		
	}
	
	/**
	 * Remove the escape characters from a line
	 */
	
	public static String removeEscapeCharacters( String original ) {
		StringBuilder newString = new StringBuilder(original.length());
		for( int i = 0 ; i < original.length() ; i++) {
			char thisChar = original.charAt(i);
			if(thisChar == '\\') {
				i++;
				thisChar = original.charAt(i);
				switch( thisChar ) {
					case 'n':
						newString.append('\n');
						break;
					case 'r':
						newString.append('\r');
						break;
					case 't':
						newString.append('\t');
						break;
					default:
						newString.append('?');
						break;
				}
			} else {
				newString.append(thisChar);
			}
		}
		return newString.toString();
	}
	
	/**
	 * Run a specific script.
	 * 
	 * @param script The script to run.
	 */
	
	public void runScript( Map<String,String> parameters, String script ) 
		throws IOException {

		try (LineNumberReader lnr = new LineNumberReader(new StringReader(script))) {
			String nextLine;
			while ((nextLine = lnr.readLine()) != null) {
				try {
					// Ignore blank lines and comments.
					if (nextLine.trim().length() == 0
							|| nextLine.startsWith("#")) {
						continue;
					}

					int commandSpaceIdx = nextLine.indexOf(' ');
					if (commandSpaceIdx == -1) {
						throw new IOException("Command not found.");
					}

					String command = nextLine.substring(0, commandSpaceIdx);
					if (command.equalsIgnoreCase("send")) {
						String outputLine =
								substituteParameters(
										parameters,
										nextLine.substring(commandSpaceIdx + 1)
								);
						outputLine = removeEscapeCharacters(outputLine);
						byte[] data = outputLine.getBytes();
						stdin.write(data);
						stdin.flush();
					} else if (command.equalsIgnoreCase("waitfor")) {
						String waitForText =
								substituteParameters(
										parameters,
										nextLine.substring(commandSpaceIdx + 1)
								);
						waitForString(waitForText);
					} else {
						throw new IOException("Command not recognised: " + command);
					}
				} catch (IOException ioe) {
					Logger.
							getLogger(getClass().toString()).
							log(Level.WARNING,
									"Error procesung script at line " + lnr.getLineNumber() + ":\"" + nextLine + "\"",
									ioe);
					throw ioe;
				}
			}
		}
	}
	
	/**
	 * Substitute the parameters in a script for the actual values.
	 * 
	 * @param values The values to substitute.
	 * @param text The text to substitute the varibles in.
	 * 
	 * @return The text with the variables substituted.
	 */
	public static String substituteParameters( final Map<String,String> values, 
			final String text ) {
		
		String textToModify = text;
		while( true ) {
			int startIdx = textToModify.indexOf("${");
			if( startIdx == -1 ) {
				break;
			}
			
			int endIdx = textToModify.indexOf("}", startIdx);
			if( endIdx == -1 ) {
				break;
			}
			
			String variableName = textToModify.substring(startIdx+2, endIdx);
			String value = values.get(variableName); 

			int newSize = textToModify.length() - (endIdx - startIdx);
			if( value != null ) {
				newSize += value.toString().length();
			}

			StringBuilder newText = new StringBuilder( newSize );
			
			newText.append(textToModify.substring(0, startIdx));
			if( value != null ) {
				newText.append(value);
			}
			newText.append(textToModify.substring(endIdx+1));
			
			textToModify = newText.toString();
		}
		
		return textToModify;
	}
	
	/**
	 * Method to wait for a particular string to arrive on the input stream. 
	 */
	
	public void waitForString( String theString ) 
		throws IOException {		
		InputWaiter waiter;
		if			( theString.startsWith("stdout") ) {
			waiter = new InputWaiter(stdout, theString.substring(7, theString.length()), WAIT_TIMEOUT);
		} else if	(theString.startsWith("stderr") ) {
			waiter = new InputWaiter(stderr, theString.substring(7, theString.length()), WAIT_TIMEOUT);
		} else {
			throw new IOException ("Unknown stream");
		}		
		
		waiter.start();
		try {
			waiter.join(WAIT_TIMEOUT);
		}
		catch( InterruptedException ie ) {
			// Do nothing, the thread could be interrupted at the end of
			// the run method.
		}
		
		if(waiter.textFound()) {
			return;
		}
		
		IOException theException = waiter.getException();
		if(theException == null ) {
			theException = new IOException("The string \"" + theString.substring(7)+
					"\" was not found on "+ theString.substring(0,6));
		}
		throw theException;
	}
}
