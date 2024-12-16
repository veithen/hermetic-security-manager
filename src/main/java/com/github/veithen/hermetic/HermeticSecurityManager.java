/*-
 * #%L
 * hermetic-security-manager
 * %%
 * Copyright (C) 2019 - 2024 Andreas Veithen-Knowles
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
package com.github.veithen.hermetic;

import java.io.FilePermission;
import java.net.SocketPermission;
import java.net.URLPermission;
import java.security.Permission;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class HermeticSecurityManager extends SecurityManager {
    private static final ThreadLocal<Boolean> inUninstall = new ThreadLocal<>();

    private final List<SafeMethod> safeMethods = new ArrayList<>();

    public HermeticSecurityManager() {
        String safeMethodsProperty = System.getProperty("hermetic.safeMethods", "");
        if (!safeMethodsProperty.isEmpty()) {
            for (String s : safeMethodsProperty.split(",")) {
                int idx = s.lastIndexOf('.');
                safeMethods.add(new SafeMethod(s.substring(0, idx), s.substring(idx + 1)));
            }
        }
    }

    private static boolean shouldCheck(Permission permission) {
        if (permission instanceof FilePermission) {
            return Pattern.compile(",")
                    .splitAsStream(((FilePermission) permission).getActions())
                    .anyMatch("execute"::equals);
        }

        if (permission instanceof URLPermission) {
            return true;
        }

        if (permission instanceof RuntimePermission) {
            return permission.getName().equals("setSecurityManager")
                    && !Boolean.TRUE.equals(inUninstall.get());
        }

        if (permission instanceof SocketPermission) {
            // Don't check for permission to resolve a host name in a TLD reserved by RFC 2606.
            // Tests may rely on this triggering an UnknownHostException. Note that this can't be
            // expressed in a policy because that only works for resolvable names.
            String host = ((SocketPermission) permission).getName();
            int idx = host.lastIndexOf(':');
            if (idx != -1) {
                host = host.substring(0, idx);
            }
            return !host.endsWith(".invalid");
        }

        return false;
    }

    private boolean needCheck(Permission permission) {
        if (!shouldCheck(permission)) {
            return false;
        }

        for (StackTraceElement stackTraceElement : Thread.currentThread().getStackTrace()) {
            for (SafeMethod safeMethod : safeMethods) {
                if (safeMethod.matches(stackTraceElement)) {
                    return false;
                }
            }
        }
        return true;
    }

    @Override
    public void checkPermission(Permission permission) {
        if (needCheck(permission)) {
            super.checkPermission(permission);
        }
    }

    @Override
    public void checkPermission(Permission permission, Object context) {
        if (needCheck(permission)) {
            super.checkPermission(permission, context);
        }
    }

    static void install() {
        System.setSecurityManager(new HermeticSecurityManager());
    }

    static void uninstall() {
        inUninstall.set(Boolean.TRUE);
        try {
            System.setSecurityManager(null);
        } finally {
            inUninstall.remove();
        }
    }
}
