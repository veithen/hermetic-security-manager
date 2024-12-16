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

import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.File;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;

import org.junit.jupiter.api.Test;

public class HermeticSecurityManagerTest {
    // We can't allow changing the security manager: the generated policy only has
    // FilePermission and SocketPermission entries, and other permissions are granted
    // by the custom SecurityManager. Using a different one would then inevitable
    // result in security exceptions.
    @Test
    @WithSecurityManager
    public void testSetSecurityManager() {
        assertThrows(
                SecurityException.class, () -> System.setSecurityManager(new SecurityManager()));
    }

    @Test
    @WithSecurityManager
    public void testConnect() {
        assertThrows(SecurityException.class, () -> new Socket("8.8.8.8", 8888));
    }

    @Test
    @WithSecurityManager
    public void testInvalidHostname() throws Exception {
        assertThrows(
                UnknownHostException.class,
                () -> new URL("http://rfc2606.invalid").openStream().close());
    }

    @Test
    @WithSecurityManager
    public void testExec() {
        assertThrows(
                SecurityException.class,
                () -> Runtime.getRuntime().exec(new String[] {"/foo/bar"}));
    }

    @Test
    @WithSecurityManager(asSafeMethod = true)
    public void testSafeMethod() {
        new File(System.getProperty("user.home"), "foobar").exists();
    }
}
