package com.masterclass.auth.notification;

public interface NotificationClient {

    void sendPasswordResetEmail(String to, String resetLink);
}