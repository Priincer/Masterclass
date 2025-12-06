package com.masterclass.auth.user.event;

public interface UserEventPublisher {

    void publishUserRegistered(UserRegisteredEvent event);

    void publishPasswordResetRequested(PasswordResetRequestedEvent event);

    void publishUserPasswordChanged(UserPasswordChangedEvent event);

}