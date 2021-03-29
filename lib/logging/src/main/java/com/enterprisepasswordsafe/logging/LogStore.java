package com.enterprisepasswordsafe.logging;

import com.enterprisepasswordsafe.model.ConfigurationOptions;
import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.EntityWithId;
import com.enterprisepasswordsafe.model.LogEventClass;
import com.enterprisepasswordsafe.model.ReservedHierarchyNodes;
import com.enterprisepasswordsafe.model.dao.ConfigurationDAO;
import com.enterprisepasswordsafe.model.dao.GroupDAO;
import com.enterprisepasswordsafe.model.dao.LoggingDAO;
import com.enterprisepasswordsafe.model.persisted.Group;
import com.enterprisepasswordsafe.model.persisted.HierarchyNode;
import com.enterprisepasswordsafe.model.persisted.LogEntry;
import com.enterprisepasswordsafe.model.persisted.Password;
import com.enterprisepasswordsafe.model.persisted.User;

import java.security.GeneralSecurityException;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.FormatStyle;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Stream;

public class LogStore {

    private final ConfigurationDAO configurationDAO;
    private final GroupDAO groupDAO;
    private final LoggingDAO loggingDAO;
    private final LogEventMailer logEventMailer;

    private final DateTimeFormatter formatter =
            DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM);

    public LogStore(DAORepository daoRepository) {
        configurationDAO = daoRepository.getConfigurationDAO();
        groupDAO = daoRepository.getGroupDAO();
        loggingDAO = daoRepository.getLoggingDAO();
        logEventMailer = new LogEventMailer(daoRepository);
    }

    public void log(final LogEventClass logEventClass, final User theUser, final Password item,
                       final String message, final boolean createTamperstamp,
                       final boolean sendEmail)
            throws GeneralSecurityException {
        LogEntry event = new LogEntry(logEventClass, theUser, item, message, createTamperstamp);
        record(event, sendEmail);
    }

    public void log(final LogEventClass logEventClass, final User theUser, final Password item,
                       final String message, final boolean sendEmail )
            throws GeneralSecurityException {
        log(logEventClass, theUser, item, message, true, sendEmail);
    }

    public void log( final LogEventClass logEventClass, final User theUser, final String message,
                        final boolean createTamperstamp )
            throws GeneralSecurityException {
        log(logEventClass, theUser, null, message, createTamperstamp, true);
    }

    public void log(LogEventClass logEventClass, final User theUser, final String message )
            throws GeneralSecurityException {
        log(logEventClass, theUser, null, message, true, true);
    }

    private void record(final LogEntry eventLogEntry, boolean sendEmail)
            throws GeneralSecurityException {
        if (sendEmail) {
            sendEmail(eventLogEntry);
        }

        loggingDAO.store(eventLogEntry);
    }

    private void sendEmail(final LogEntry eventLogEntry)
            throws GeneralSecurityException {
        String sendEmails = configurationDAO.get(getSmtpConfigurationProperty(eventLogEntry));
        if(sendEmails == null || sendEmails.charAt(0) != 'N') {
            try {
                synchronized (logEventMailer) {
                    logEventMailer.sendEmail(eventLogEntry);
                }
            } catch (Exception ex) {
                LogEntry log = new LogEntry("Unable to send audit Email (Reason:"+ex.getMessage()+")");
                record(log, false);
            }
        }
    }

    private String getSmtpConfigurationProperty(LogEntry logEntry) {
        return ConfigurationOptions.SMTP_ENABLED.getPropertyName() +
                '.' + logEntry.getLogEventClass().getConfigurationSuffix();
    }

    public List<EventsForDay> getEventsForDateRange(final Date startDate,
                                                    final Date endDate, final User userLimit, final Password itemLimit,
                                                    final User fetchingUser, final boolean includePersonal,
                                                    final boolean validateTamperstamp)
            throws GeneralSecurityException {
        Group adminGroup = groupDAO.getAdminGroup(fetchingUser);

        Stream<LogEntry> logStream = loggingDAO.getEventsForDateRange(startDate, endDate).stream();
        logStream = addFilter(logStream, userLimit, LogEntry::getUser);
        logStream = addFilter(logStream, itemLimit, LogEntry::getItem);
        if(!includePersonal) {
            logStream = logStream.filter(logEntry -> isNotPersonal(logEntry.getItem()));
        }
        Map<LocalDate, List<LogEntry>> logEntries =
                processResults(logStream, fetchingUser, adminGroup, validateTamperstamp);

        List<EventsForDay> events = new ArrayList<>();
        for(Map.Entry<LocalDate, List<LogEntry>> entry : logEntries.entrySet()) {
            events.add(new EventsForDay(entry.getKey(), entry.getValue()));
        }

        events.sort(Comparator.comparing(o -> o.date));
        return events;
    }

    private Stream<LogEntry> addFilter(Stream<LogEntry> stream, EntityWithId matchCriteria,
                                       Function<LogEntry, EntityWithId> entityExtractor) {
        if (matchCriteria == null) {
            return stream;
        }
        return stream.filter(logEntry -> {
            EntityWithId entity = entityExtractor.apply(logEntry);
            if (entity == null) {
                return false;
            }
            return matchCriteria.getId().equals(entity.getId());
        });
    }

    private Map<LocalDate, List<LogEntry>> processResults(final Stream<LogEntry> results, User fetchingUser,
                                                          Group adminGroup, final boolean validateTamperstamp) {
        Map<LocalDate, List<LogEntry>> dateToEventsMap = new HashMap<>();
        results.forEach(entry -> {
            LocalDate date = entry.getTimestamp().toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
            List<LogEntry> entryList;
            synchronized (dateToEventsMap) {
                entryList = dateToEventsMap.computeIfAbsent(date, k -> new ArrayList<>());
                entryList.add(entry);
            }
        });

        return dateToEventsMap;
    }

    private boolean isNotPersonal(Password password) {
        if(password == null) {
            return true;
        }

        HierarchyNode passwordParent = password.getParentNode();
        while(passwordParent != null && !ReservedHierarchyNodes.SYSTEM_ROOT.matches(passwordParent)) {
            passwordParent = passwordParent.getParent();
        }

        return passwordParent != null;
    }


    public class EventsForDay {
        private final LocalDate date;
        private final String humanReadableDate;
        private final List<LogEntry> events;

        public EventsForDay( final LocalDate date, final List<LogEntry> events ) {
            this.date = date;
            this.events = events;
            humanReadableDate = formatter.format(date);
        }

        public List<LogEntry> getEvents() {
            return events;
        }

        public String getHumanReadableDate() {
            return humanReadableDate;
        }
    }
}
