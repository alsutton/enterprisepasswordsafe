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

import java.io.IOException;
import java.io.InputStream;
import java.io.LineNumberReader;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.io.StringReader;
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
	 * The size of the pushback buffer
	 */
	
	private static final int PUSHBACK_SIZE = 1024;
	
	/**
	 * The stdin stream from the endpoint.
	 */
	
	private InputStream stdout;
	
	/**
	 * The stderr stream from the endpoint.
	 */
	
	private InputStream stderr;
	
	/**
	 * The output stream to the endpoint.
	 */
	
	private OutputStream stdin;
	
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
		StringBuffer newString = new StringBuffer(original.length());
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
	
		LineNumberReader lnr = new LineNumberReader( new StringReader( script ) );
		try {
			String nextLine;
			while((nextLine = lnr.readLine()) != null) {
				try {
					// Ignore blank lines and comments.
					if( nextLine.trim().length() == 0 
					||	nextLine.startsWith("#") ) {
						continue;
					}
					
					int commandSpaceIdx = nextLine.indexOf(' ');
					if( commandSpaceIdx == -1 ) {
						throw new IOException( "Command not found.");
					}
					
					String command = nextLine.substring(0, commandSpaceIdx);
					if			(command.equalsIgnoreCase("send") ) {
						String outputLine = 
							substituteParameters(
									parameters,
									nextLine.substring(commandSpaceIdx+1)
								);
						outputLine = removeEscapeCharacters(outputLine);
						byte[] data = outputLine.getBytes();
						stdin.write(data);
						stdin.flush();
					} else if	(command.equalsIgnoreCase("waitfor") ) {
						String waitForText = 
							substituteParameters(
									parameters,
									nextLine.substring(commandSpaceIdx+1)
								);
						waitForString(waitForText);
					} else {
						throw new IOException("Command not recognised: "+command);
					}					
				} catch( IOException ioe ) {
					Logger.
						getLogger(getClass().toString()).
							log(Level.WARNING, 
								"Error procesung script at line "+lnr.getLineNumber()+":\""+nextLine+"\"",
								ioe);
					throw ioe;
				}
			}
		} finally {
			lnr.close();
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

			StringBuffer newText = new StringBuffer( newSize );
			
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
			waiter = new InputWaiter(stdout, theString.substring(7, theString.length()));
		} else if	(theString.startsWith("stderr") ) {
			waiter = new InputWaiter(stderr, theString.substring(7, theString.length()));			
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
			theException = new IOException( 
					"The string \""+
					theString.substring(7)+
					"\" was not found on "+
					theString.substring(0,6));
		}
		
		throw theException;
	}
	
	/**
	 * Class which waits for a particular string on a Reader.
	 */
	
	private class InputWaiter extends Thread {

		/**
		 * The reader which is being read.
		 */
		
		private PushbackInputStream reader;
		
		/**
		 * The text being waited for.
		 */
		
		private String text;
		
		/**
		 * Flag to say if the text has been found.
		 */
		
		private boolean textFound = false;
		
		/**
		 * Storage for any IOExceptions which occur.
		 */
		
		private IOException ioException;
		
		/**
		 * Constructor
		 */
		
		InputWaiter( InputStream theInput, String theText ) {
			reader = new PushbackInputStream(theInput, PUSHBACK_SIZE);
			text = theText;
		}
		
		/**
		 * The method to read the reader and look for the text.
		 */
		
		public void run() {
			long startTime = System.currentTimeMillis();
			
			int searchTextLength = text.length();
			StringBuffer textHold = new StringBuffer( searchTextLength );
			int currentFoundIdx = 0;
			try {
				int thisChar;
				while( true ) {
					if( (thisChar = reader.read()) == -1 ) {
						if( System.currentTimeMillis() - startTime < WAIT_TIMEOUT) {
							Thread.sleep(100);
							continue;						
						} else {
							return;
						}
					}
					char thisCharacter = (char) thisChar;
					if(thisCharacter == text.charAt(currentFoundIdx)) {
						textHold.insert(0, thisCharacter);					
						currentFoundIdx++;
						if( currentFoundIdx == searchTextLength ) {
							textFound = true;
							break;
						}
					} else {
						if( textHold.length() > 0 ) {
							reader.unread(textHold.toString().getBytes(), 1, textHold.length()-1);
							textHold.setLength(0);
						}
						currentFoundIdx = 0;
					}
				}
			} catch( IOException ioe ) {
				ioException = ioe;
			} catch( InterruptedException ie ) {
				
			}
		}
		
		/**
		 * Return a flag to see if the text was found or not.
		 * 
		 * @return true if the text was found. False if not.
		 */
		
		boolean textFound() {
			return textFound;
		}
		
		/**
		 * Returns any IOException thrown during processing.
		 * 
		 * @return Any exception thrown, or null if no exception was thrown.
		 */
		
		IOException getException() {
			return ioException;
		}
	}
}
