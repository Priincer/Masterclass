package com.masterclass.auth.notification;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class LoggingNotificationClient implements NotificationClient {

    @Override
    public void sendPasswordResetEmail(String to, String resetLink) {
       //TODO  In der Entwicklung nur loggen, später durch echten HTTP-Client ersetzen
        log.info("Would send password reset email to '{}' with link: {}", to, resetLink);
    }
}