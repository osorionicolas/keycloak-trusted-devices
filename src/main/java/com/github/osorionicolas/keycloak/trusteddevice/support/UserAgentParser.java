package com.github.osorionicolas.keycloak.trusteddevice.support;

import lombok.extern.jbosslog.JBossLog;
import ua_parser.OS;
import ua_parser.Parser;
import ua_parser.UserAgent;

@JBossLog
public class UserAgentParser {

    private static final Parser USER_AGENT_PARSER;

    static {
        Parser parser = null;
        try {
            parser = new Parser();
        } catch (Exception e) {
            log.errorf(e, "Could not initialize user_agent parser");
        }
        USER_AGENT_PARSER = parser;
    }

    public static UserAgent parseUserAgent(String userAgentString) {

        if (USER_AGENT_PARSER == null) {
            return null;
        }

        return USER_AGENT_PARSER.parseUserAgent(userAgentString);
    }

    public static OS parseOperationSystem(String userAgentString) {

        if (USER_AGENT_PARSER == null) {
            return null;
        }

        return USER_AGENT_PARSER.parseOS(userAgentString);
    }
}