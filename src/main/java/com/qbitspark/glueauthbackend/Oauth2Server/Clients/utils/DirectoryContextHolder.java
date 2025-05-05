package com.qbitspark.glueauthbackend.Oauth2Server.Clients.utils;

import java.util.UUID;

/**
 * Holds directory context in a ThreadLocal variable.
 * This allows directory ID to be available throughout the request processing.
 */
public class DirectoryContextHolder {

    private static final ThreadLocal<UUID> DIRECTORY_CONTEXT = new ThreadLocal<>();

    public static void setDirectoryId(UUID directoryId) {
        DIRECTORY_CONTEXT.set(directoryId);
    }

    public static UUID getDirectoryId() {
        return DIRECTORY_CONTEXT.get();
    }

    public static void clear() {
        DIRECTORY_CONTEXT.remove();
    }

    public static boolean hasContext() {
        return getDirectoryId() != null;
    }
}