package com.masterclass.auth.user.event;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class LoggingUserEventPublisher implements UserEventPublisher {

    @Override
    public void publishUserRegistered(UserRegisteredEvent event) {
        log.info("UserRegisteredEvent published: {}", event);
    }
}