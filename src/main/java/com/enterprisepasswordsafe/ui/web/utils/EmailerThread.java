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

import java.sql.SQLException;
import java.util.Properties;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.mail.Message;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import com.enterprisepasswordsafe.engine.database.ConfigurationDAO;
import com.enterprisepasswordsafe.engine.database.ConfigurationOption;


/**
 * Class to handling emailing messages via a thread.
 */

public class EmailerThread extends Thread {
    /**
     * Whether or not SMTP emails are enabled.
     */

    private final boolean smtpEnabled;

    /**
     * The Set of email addresses to send the email to.
     */

    private final Set<String> emailAddresses;

    /**
     * The subject of the message to be sent.
     */

    private final String subject;

    /**
     * The message to be sent.
     */

    private final String message;

    /**
     * The SMTP host.
     */

    private final String smtpHost;

    /**
     * The SMTP sender.
     */

    private final InternetAddress smtpSender;

    /**
     * Constructor. Stores the message and the list of addresses to send the
     * email to.
     *
     * @param newEmailAddresses
     *            The email addresses to send the mail to.
     * @param newSubject
     *            The subject for the email.
     * @param newMessage
     *            The message to send.
     *
     * @throws SQLException Thrown if there is a problem getting the configuration properties
     *  from the database.
     * @throws AddressException Thrown if there is a problem with an Email address.
     */

    public EmailerThread(final Set<String> newEmailAddresses, final String newSubject,final String newMessage)
        throws SQLException, AddressException {
    	ConfigurationDAO cDAO = ConfigurationDAO.getInstance();

        final String smtpEnabledString = cDAO.get(ConfigurationOption.SMTP_ENABLED);
        smtpEnabled = (smtpEnabledString != null && smtpEnabledString.equals("Y"));

        // Check email has been enabled
        smtpHost = ConfigurationDAO.getValue(ConfigurationOption.SMTP_HOST);
        final String smtpSenderString = cDAO.get(ConfigurationOption.SMTP_FROM);
        smtpSender = new InternetAddress(smtpSenderString);

        emailAddresses = newEmailAddresses;
        subject = newSubject;
        message = newMessage;
    }

    /**
     * The run method, emails the message to the user.
     */

    @Override
	public void run() {
        if (!smtpEnabled) {
            return;
        }

        Logger theLogger = Logger.getLogger(getClass().getName());
        for(String address: emailAddresses) {
            if (address == null || address.length() == 0)
                continue;

            try {
                Properties props = new Properties();
                props.put("mail.smtp.host", smtpHost);
                Session s = Session.getInstance(props, null);

                MimeMessage mimeMessage = new MimeMessage(s);
                mimeMessage.setFrom(smtpSender);
                InternetAddress to = new InternetAddress(address);
                mimeMessage.addRecipient(Message.RecipientType.TO, to);

                mimeMessage.setSubject(subject);
                mimeMessage.setText(message);

                Transport.send(mimeMessage);
            } catch (Exception ex) {
                theLogger.log(Level.WARNING, "Error Emailing "+address, ex);
            }
        }
    }
}
