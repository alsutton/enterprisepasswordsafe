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

package com.enterprisepasswordsafe.ui.web.servlets;

import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.font.FontRenderContext;
import java.awt.geom.Rectangle2D;
import java.awt.image.BufferedImage;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;

import javax.imageio.ImageIO;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import com.enterprisepasswordsafe.engine.database.AccessControl;
import com.enterprisepasswordsafe.engine.database.AccessControlDAO;
import com.enterprisepasswordsafe.engine.database.HistoricalPasswordDAO;
import com.enterprisepasswordsafe.engine.database.PasswordBase;
import com.enterprisepasswordsafe.engine.database.PasswordDAO;
import com.enterprisepasswordsafe.engine.database.User;
import com.enterprisepasswordsafe.ui.web.utils.SecurityUtils;
import com.enterprisepasswordsafe.ui.web.utils.ServletUtils;


/**
 * Obtains the requested password information and sends the user to the ViewPassword page.
 */

public final class ViewPasswordImage extends HttpServlet {

    /**
	 *
	 */
	private static final long serialVersionUID = -5824139595352894340L;

    /**
     * @throws UnsupportedEncodingException
     * @see com.enterprisepasswordsafe.passwordsafe.servlets.NoResponseBaseServlet#serviceRequest
     *      (java.sql.Connection, javax.servlet.http.HTTPServletRequest)
     */
    @Override
	protected void doGet(final HttpServletRequest request, final HttpServletResponse response)
            throws IOException {
        String id = ServletUtils.getInstance().getParameterValue(request, SharedParameterNames.PASSWORD_ID_PARAMETER);
        String dt = request.getParameter(BaseServlet.DATE_TIME_PARAMETER);

        String passwordText;

        try {
	        User user = SecurityUtils.getRemoteUser(request);

	        AccessControl ac;
	        if (user.isAdministrator() || user.isSubadministrator()) {
	            ac = AccessControlDAO.getInstance().getAccessControlEvenIfDisabled(user, id);
	        } else {
	            ac = AccessControlDAO.getInstance().getAccessControl(user, id);
	        }

	        PasswordBase password;
	        if (dt == null || dt.length() == 0) {
	            password = PasswordDAO.getInstance().getByIdEvenIfDisabled(ac, id);
	        } else {
	        	long timestamp = Long.parseLong(dt);
	            password = HistoricalPasswordDAO.getInstance().getByIdForTime(ac, id, timestamp);
	            request.setAttribute(BaseServlet.DATE_TIME_PARAMETER, dt);
	        }

	        if (ac == null) {
	        	response.sendError(HttpServletResponse.SC_FORBIDDEN);
	            return;
	        }

	        passwordText = password.getPassword();
        } catch(Exception ex) {
        	log("Error creating password image", ex);
        	return;
        }

        BufferedImage buffer = new BufferedImage(1,1,BufferedImage.TYPE_INT_RGB);
        Graphics2D graphics = buffer.createGraphics();
        Font font = graphics.getFont();
        graphics.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        FontRenderContext fc = graphics.getFontRenderContext();

        if( passwordText == null || passwordText.length() == 0 ) {
        	passwordText = "*** A password has not been set ***";
        }
        Rectangle2D bounds = font.getStringBounds(passwordText,fc);

        int width = (int) bounds.getWidth();
        int height = (int) bounds.getHeight();
        buffer = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        graphics = buffer.createGraphics();
        graphics.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
       	graphics.setColor(Color.WHITE);
        graphics.fillRect(0,0,width,height);
       	graphics.setColor(Color.BLACK);
        graphics.drawString(passwordText,0,(int)-bounds.getY());

        response.setContentType("image/jpeg");
        OutputStream os = response.getOutputStream();
        ImageIO.write(buffer, "jpeg", os);
        os.close();

        // Backpush the current otid as the nextotid to
        // avoid problems with ViewPassword
        HttpSession session = request.getSession();
        request.setAttribute("nextOtid", session.getAttribute("otid"));
    }

    /**
     * @see javax.servlet.Servlet#getServletInfo()
     */
    @Override
	public String getServletInfo() {
        return "Gets a graphical representation of a password.";
    }
}
