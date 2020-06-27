package com.enterprisepasswordsafe.engine.scripting;

import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;

class InputWaiter extends Thread {

    private static final int PUSHBACK_SIZE = 1024;
    private final PushbackInputStream reader;
    private final String text;
    private final long waitTimeout;
    private boolean textFound = false;
    private IOException ioException;

    InputWaiter(InputStream theInput, String theText, long waitTimeout) {
        reader = new PushbackInputStream(theInput, PUSHBACK_SIZE);
        text = theText;
        this.waitTimeout = waitTimeout;
    }

    public void run() {
        long startTime = System.currentTimeMillis();

        int searchTextLength = text.length();
        StringBuilder textHold = new StringBuilder( searchTextLength );
        int currentFoundIdx = 0;
        try {
            int thisChar;
            while( true ) {
                if( (thisChar = reader.read()) == -1 ) {
                    if( System.currentTimeMillis() - startTime < waitTimeout) {
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
            // Continue if interrupted
        }
    }

    boolean textFound() {
        return textFound;
    }

    IOException getException() {
        return ioException;
    }
}
