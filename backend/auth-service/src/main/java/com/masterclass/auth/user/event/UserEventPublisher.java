package com.masterclass.auth.user.event;

public interface UserEventPublisher {

    void publishUserRegistered(UserRegisteredEvent event);

}