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

/*
 * DatabaseDateFormatter.java
 *
 * Created on 18 May 2003, 09:13
 */

package com.enterprisepasswordsafe.ui.web.utils;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

/**
 *  Utility classes associated with date formatting.
 *
 * @author al
 */
public final class DateFormatter {

	/**
	 * The shared empty string returned of a null date is passed.
	 */

	private static final String EMPTY_STRING = "";

	/**
	 * The number of milliseconds in a day.
	 */

	private static final long MILLIS_IN_A_DAY = 24 * 60 * 60 * 1000;

    /**
     * The months of the year.
     */

    public static final String[] MONTHS = {"Jan", "Feb", "Mar", "Apr", "May",
            "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    /**
     * The length of a date in a datetime section.
     */

    public static final int DATE_LENGTH = 8;

    /**
     * The start location of the year information in a string.
     */

    public static final int YEAR_START_POSITION = 0;

    /**
     * The end position of the year information in a string.
     */

    public static final int YEAR_END_POSITION = 4;

    /**
     * The start location of the month information in a string.
     */

    public static final int MONTH_START_POSITION = 4;

    /**
     * The end position of the month information in a string.
     */

    public static final int MONTH_END_POSITION = 6;

    /**
     * The start location of the day information in a string.
     */

    public static final int DAY_START_POSITION = 6;

    /**
     * The end position of the day information in a string.
     */

    public static final int DAY_END_POSITION = 8;

    /**
     * The start location of the hour information in a string.
     */

    public static final int HOUR_START_POSITION = 8;

    /**
     * The end position of the hour information in a string.
     */

    public static final int HOUR_END_POSITION = 10;

    /**
     * The start location of the minute information in a string.
     */

    public static final int MINUTE_START_POSITION = 10;

    /**
     * The end position of the month information in a string.
     */

    public static final int MINUTE_END_POSITION = 12;

    /**
     * The start location of the second information in a string.
     */

    public static final int SECOND_START_POSITION = 12;

    /**
     * The end position of the second information in a string.
     */

    public static final int SECOND_END_POSITION = 14;

    /**
     * The number of milliseconds in a minute.
     */

    public static final int MILLIS_IN_MINUTE = 60000;

    /**
     * The number of milliseconds in a second.
     */

    public static final int MILLIS_IN_SECOND = 1000;

    /**
     * The number of seconds in a minute.
     */

    public static final int SECONDS_IN_MINUTE = 60;

    /**
     * Private constructor to prevent instanciation by other objects.
     */

    private DateFormatter() {
    }

    /**
     * Get midnight today
     */

    private static Calendar getMidnight() {
    	Calendar now = Calendar.getInstance();
    	now.set(Calendar.HOUR_OF_DAY, 0);
    	now.set(Calendar.MINUTE, 0);
    	now.set(Calendar.SECOND, 0);
    	now.set(Calendar.MILLISECOND, 0);
    	return now;
    }

    /**
     * Get the date string representation of today.
     *
     * @return The date string representation of today.
     */

    public static long getToday() {
        return getMidnight().getTimeInMillis();
    }

    /**
     * Get the date for a specific number of days in the future
     *
     * @param daysToAdd
     *            The number of days in the future to get the date for.
     *
     * @return The string representation of that date.
     */

    public static long getDateInFuture(final int daysToAdd) {
    	Calendar nowCal = getMidnight();
    	nowCal.add(Calendar.DAY_OF_MONTH, daysToAdd);
    	return nowCal.getTimeInMillis();
    }

    /**
     * Get the date for a specific number of days in the past
     *
     * @param daysToSubtract
     *            The number of days in the past to get the date for.
     *
     * @return The string representation of that date.
     */

    public static long getDateInPast(final int daysToSubtract) {
    	return getDateInFuture(0 - daysToSubtract);
    }

    /**
     * Get the time and date string representation of now.
     *
     * @return The time and date string representation of now.
     */

    public static long getNow() {
    	Calendar cal = Calendar.getInstance();
    	return cal.getTimeInMillis();
    }

    /**
     * Convert a string to a date.
     *
     * @param date
     *            The String date to convert.
     *
     * @return The Date representation.
     *
     * @throws ParseException
     *             Thrown if there is a problem parsing the date.
     */

    public static Date convertToDate(final String date)
            throws ParseException {
        SimpleDateFormat dayFormatter = new SimpleDateFormat("yyyyMMdd");
        return dayFormatter.parse(date);
    }

    /**
     * Get a specified number of seconds ago.
     *
     * @param secondsToSubtract
     *            The number of seconds in the past to get the time for.
     *
     * @return The string representation of that time.
     */

    public static long getTimeInPast(final int secondsToSubtract) {
    	Calendar cal = Calendar.getInstance();
    	cal.add(Calendar.SECOND, 0 - secondsToSubtract);
    	return cal.getTimeInMillis();
    }

    /**
     * Gets the text for a specific yyyymmdd text.
     *
     * @param date
     *            The date text to return the text for.
     *
     * @return The text for the specified date.
     */

    public static String convertToString(final long date) {
    	if( date == Long.MAX_VALUE || date == Long.MIN_VALUE ) {
    		return EMPTY_STRING;
    	}

    	Calendar cal = Calendar.getInstance();
    	cal.setTimeInMillis(date);
        SimpleDateFormat sdf = new SimpleDateFormat("dd-MMM-yyyy");
        return sdf.format(cal.getTime());
    }

    /**
     * Extracts the time from a datetime string and converts it to human
     * readable form.
     *
     * @param datetime
     *            The date text to extract the time from.
     *
     * @return The text for the time from the datetime string.
     */

    public static String convertTimeFromDateTimeToString(final long datetime) {
    	if( datetime == Long.MAX_VALUE || datetime == Long.MIN_VALUE ) {
    		return EMPTY_STRING;
    	}

    	Calendar cal = Calendar.getInstance();
    	cal.setTimeInMillis(datetime);
        SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss");
        return sdf.format(cal.getTime());
    }

    /**
     * Get the text for a specified date and time time.
     *
     * @param datetime
     *            The date in the form yyyymmddHHMMSS.
     *
     * @return A user readable text equivalent.
     */

    public static String convertToDateTimeString(final long datetime) {
        StringBuffer string = new StringBuffer();

        string.append(convertTimeFromDateTimeToString(datetime));
        string.append(" on ");
        string.append(convertToString(datetime));

        return string.toString();
    }

    /**
     * Takes a day, month, and year and converts it into a time in milliseconds since the epoch.
     *
     * @param day The day for the combined string.
     * @param month The month for the combined string.
     * @param year The year for the combined string.
     *
     * @return The time in milliseconds since the epoch.
     */

    public static long combineDate(final String day, final String month, final String year) {
        if (day == null   || day.length() == 0
         || month == null || month.length() == 0
         || year == null  || year.length() == 0) {
            return Long.MIN_VALUE;
        }

        Calendar cal = getMidnight();
        cal.set(Calendar.DAY_OF_MONTH, Integer.parseInt(day));
        cal.set(Calendar.MONTH, Integer.parseInt(month));
        cal.set(Calendar.YEAR, Integer.parseInt(year));
        return cal.getTimeInMillis();
    }

    /**
     * Strips out the time from any long representation of a date
     */

    public static long stripTime(final long datetime) {
    	long strippedDate = datetime / MILLIS_IN_A_DAY;
    	return strippedDate * MILLIS_IN_A_DAY;
    }

    /**
     * Return the number of days in the past a specific time is
	 *
     * @param time The time to get the value for.
	 *
     * @return The number of days in the past the time is.
     */
	public static long daysInPast(long date) {
		return (date - getNow()) / MILLIS_IN_A_DAY;
	}
}
