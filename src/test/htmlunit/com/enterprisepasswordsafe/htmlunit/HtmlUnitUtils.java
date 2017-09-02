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

package com.enterprisepasswordsafe.htmlunit;

import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlOption;
import com.gargoylesoftware.htmlunit.html.HtmlRadioButtonInput;
import com.gargoylesoftware.htmlunit.html.HtmlSelect;

/**
 * Utility classes for dealing with HtmlUnit
 */
public final class HtmlUnitUtils {

    /**
     * Set a set of radio buttons to a specific value.
     *
     * @param form The form which contains the radio buttons.
     * @param fieldName The name of the radio buttons to set.
     * @param value The value to set the buttons to.
     */

    public static void setRadioButton(HtmlForm form, final String fieldName, final String value) {
        for(HtmlRadioButtonInput button : form.getRadioButtonsByName(fieldName)) {
            if(value.equals(button.getValueAttribute())) {
                button.setChecked(true);
                return;
            }
        }
        throw new RuntimeException("Value "+value+" was not found in "+fieldName);
    }

    /**
     * Get the selected value in a set of radio buttons
     *
     * @param form The form to select the element from.
     * @param fieldName The name of the radio buttons.
     *
     * @return The value of the currently selected radio button, or null if no selection was found.
     */
    public static String getSelectedRadioValue(final HtmlForm form, final String fieldName) {
        for(HtmlRadioButtonInput button : form.getRadioButtonsByName(fieldName)) {
            if(button.isDefaultChecked()) {
                return button.getValueAttribute();
            }
        }
        return null;
    }

    /**
     * Set the selected option on a select list.
     */

    public static void setSelectedOptions(final HtmlForm form, final String fieldName, final String value) {
        HtmlSelect select = form.getSelectByName(fieldName);
        HtmlOption option = select.getOptionByValue(value);
        select.setSelectedAttribute(option, true);
    }

    public static WebClient createWebClient() {
        WebClient wc = new WebClient();
        wc.getOptions().setRedirectEnabled(true);
        wc.getOptions().setJavaScriptEnabled(false);
        return wc;
    }

    public static void closeWebClient(WebClient wc) {
        if(wc != null) {
            wc.closeAllWindows();
        }
    }
}
