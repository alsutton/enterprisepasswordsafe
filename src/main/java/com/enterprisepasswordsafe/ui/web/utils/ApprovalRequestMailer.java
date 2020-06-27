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

package com.enterprisepasswordsafe.ui.web.utils;

import com.enterprisepasswordsafe.database.*;

import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.sql.SQLException;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * The class responsible for mailing notifications that a password has been accessed. Mailing
 * is performed in a seperate thread to the main one.
 */
public class ApprovalRequestMailer
	extends Thread {

	/**
	 * The list of mailers currently working.
	 */

	private static final List<ApprovalRequestMailer> activeMailers = new ArrayList<ApprovalRequestMailer>();

	/**
	 * The set of approvers to send the messages to
	 */

	private final Set<AccessRole.ApproverSummary> recipients;

	/**
	 * The SMTP server to send the mail via.
	 */

	private final String smtpServer;

	/**
	 * The sender for the messages.
	 */

	private String sender;

	/**
	 * The subject for all of the emails.
	 */

	private final String subject;

	/**
	 * The message Text
	 */

	private final String messageText;

	/**
	 * Constructors, stores the information and starts the sender.
	 */
	public ApprovalRequestMailer(final Set<AccessRole.ApproverSummary> approvers, final User requester,
                                 final Password password, final RestrictedAccessRequest request,
                                 final String approvalURL)
		throws SQLException {

        smtpServer = ConfigurationDAO.getValue(ConfigurationOption.SMTP_HOST);

		sender = requester.getEmail();
		if( sender == null ) {
			sender = "eps@enterprise-password-safe.com";
		}
		subject = "EPS Access Request : "+request.getRequestId();
		recipients = approvers;

		StringBuffer messageTextBuffer = new StringBuffer();
		messageTextBuffer.append(requester.getUserName());
		String fullName = requester.getFullName();
		if(fullName != null) {
			messageTextBuffer.append(" (");
			messageTextBuffer.append(fullName);
			messageTextBuffer.append(")");
		}
		messageTextBuffer.append(" has requested access to ");
		messageTextBuffer.append(password.toString());
		messageTextBuffer.append(" for the following reason;\n\n");
		messageTextBuffer.append(request.getReason());

		messageTextBuffer.append("\n\nPlease visit the URL below to approve or deny this request;\n\n");
		messageTextBuffer.append(approvalURL);

		messageText = messageTextBuffer.toString();

		activeMailers.add(this);
	}

	/**
	 * Run method. Tries to send all emails individually so if there is a problem with one
	 * the others can get out.
	 */

	@Override
	public void run() {
		for(AccessRole.ApproverSummary summary : recipients) {
			String mailAddress = summary.getEmail();
			try {
				sendEmail(mailAddress);
			} catch(Exception ex) {
	            Logger.
	            	getLogger(ApprovalRequestMailer.class.getName()).
                    	log(Level.SEVERE, "Unable to send mail to "+mailAddress, ex);

			}
		}
		activeMailers.remove(this);
	}

    /**
     * Sends an Email to to register an event.
     *
     * @param recipient The recipient to sent the email to.
     *
     * @throws AddressException
     *             Thrown if there is a problem sending the event Email.
     * @throws MessagingException
     *             Thrown if there is a problem sending the event Email.
     */

    public void sendEmail(final String recipient)
    	throws AddressException, MessagingException {
    	if( recipient == null )
    		return;

    	if( smtpServer == null ) {
    		throw new MessagingException("An SMTP Server has not been specified");
    	}

        Properties props = new Properties();
        props.put("mail.smtp.host", smtpServer);
        Session s = Session.getInstance(props, null);

        MimeMessage message = new MimeMessage(s);

        InternetAddress from = new InternetAddress(sender);
        message.setFrom(from);

        StringTokenizer recipientTokenizer = new StringTokenizer(recipient, ";");
        while (recipientTokenizer.hasMoreTokens()) {
            InternetAddress to = new InternetAddress(recipientTokenizer
                    .nextToken());
            message.addRecipient(Message.RecipientType.TO, to);
        }

        message.setSubject(subject);
        message.setText(messageText);

        Transport.send(message);
    }
}
