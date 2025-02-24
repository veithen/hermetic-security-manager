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

final class SafeMethod {
    private final String className;
    private final String methodName;

    SafeMethod(String className, String methodName) {
        this.className = className;
        this.methodName = methodName;
    }

    boolean matches(StackTraceElement stackTraceElement) {
        return className.equals(stackTraceElement.getClassName())
                && methodName.equals(stackTraceElement.getMethodName());
    }
}
