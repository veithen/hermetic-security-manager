/*-
 * #%L
 * hermetic-security-manager
 * %%
 * Copyright (C) 2019 - 2021 Andreas Veithen
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

import java.lang.reflect.AnnotatedElement;
import java.lang.reflect.Method;

import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.InvocationInterceptor;
import org.junit.jupiter.api.extension.ReflectiveInvocationContext;

public class WithSecurityManagerExtension implements InvocationInterceptor {
    @Override
    public void interceptTestMethod(
            Invocation<Void> invocation,
            ReflectiveInvocationContext<Method> invocationContext,
            ExtensionContext extensionContext)
            throws Throwable {
        if (extensionContext.getElement().isPresent()) {
            AnnotatedElement element = extensionContext.getElement().get();
            WithSecurityManager annotation = element.getAnnotation(WithSecurityManager.class);
            if (annotation != null && annotation.asSafeMethod()) {
                Method method = (Method) element;
                System.setProperty(
                        "hermetic.safeMethods",
                        method.getDeclaringClass().getName() + "." + method.getName());
            }
        }
        HermeticSecurityManager.install();
        try {
            invocation.proceed();
        } finally {
            HermeticSecurityManager.uninstall();
            System.getProperties().remove("hermetic.safeMethods");
        }
    }
}
