package com.qbitspark.glueauthbackend.Oauth2Server.Clients.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;

public class DirectoryContextHolder {
    private static final Logger logger = LoggerFactory.getLogger(DirectoryContextHolder.class);
    private static final ThreadLocal<UUID> DIRECTORY_CONTEXT = new ThreadLocal<>();

    public static void setDirectoryId(UUID directoryId) {
        logger.debug("Setting directory ID: {}", directoryId);
        DIRECTORY_CONTEXT.set(directoryId);
    }

    public static UUID getDirectoryId() {
        UUID directoryId = DIRECTORY_CONTEXT.get();
        if (directoryId == null) {
            logger.debug("No directory ID found in current thread context");
        }
        return directoryId;
    }

    public static void clear() {
        logger.debug("Clearing directory context");
        DIRECTORY_CONTEXT.remove();
    }
}