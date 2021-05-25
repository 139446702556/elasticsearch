/*
 * Licensed to Elasticsearch under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.elasticsearch.bootstrap;

import org.elasticsearch.common.SuppressForbidden;

import java.io.FilePermission;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Permissions;

public class FilePermissionUtils {

    /** no instantiation */
    private FilePermissionUtils() {}

    /**
     * Add access to single file path
     * 给指定文件添加访问权限（绝对和相对路径两种）
     * @param policy current policy to add permissions to
     * @param path the path itself
     * @param permissions set of file permissions to grant to the path
     */
    @SuppressForbidden(reason = "only place where creating Java-9 compatible FilePermission objects is possible")
    public static void addSingleFilePath(Permissions policy, Path path, String permissions) throws IOException {
        policy.add(new FilePermission(path.toString(), permissions));
        if (Files.exists(path)) {
            /*
             * The file permission model since JDK 9 requires this due to the removal of pathname canonicalization. See also
             * https://github.com/elastic/elasticsearch/issues/21534.
             */
            final Path realPath = path.toRealPath();
            if (path.toString().equals(realPath.toString()) == false) {
                policy.add(new FilePermission(realPath.toString(), permissions));
            }
        }
    }

    /**
     * Add access to path with direct and/or recursive access. This also creates the directory if it does not exist.
     *
     * @param policy            current policy to add permissions to
     * @param configurationName the configuration name associated with the path (for error messages only)
     * @param path              the path itself
     * @param permissions       set of file permissions to grant to the path
     * @param recursiveAccessOnly   indicates if the permission should provide recursive access to files underneath
     */
    @SuppressForbidden(reason = "only place where creating Java-9 compatible FilePermission objects is possible")
    public static void addDirectoryPath(Permissions policy, String configurationName, Path path, String permissions,
                                        boolean recursiveAccessOnly) throws IOException {
        // paths may not exist yet, this also checks accessibility
        try {
            // 检测指定的目录是否具有read权限，如果指定目录还不存在，则会进行递归创建
            Security.ensureDirectoryExists(path);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to access '" + configurationName + "' (" + path + ")", e);
        }

        // For some file permissions (data.path) we create a Permissions object that only checks the concrete
        // path. Adding the directory would only create more overhead for this fast path.
        if (recursiveAccessOnly == false) {
            // add access for path itself
            // 添加对指定路径的访问权限
            policy.add(new FilePermission(path.toString(), permissions));
        }
        // 添加对指定路径下的文件的访问权限
        policy.add(new FilePermission(path.toString() + path.getFileSystem().getSeparator() + "-", permissions));
        /*
         * The file permission model since JDK 9 requires this due to the removal of pathname canonicalization. See also
         * https://github.com/elastic/elasticsearch/issues/21534.
         */
        final Path realPath = path.toRealPath();
        // 如果当前给定path与其绝对路径不相同，则对其绝对路径在进行一波权限设置（path可能是相对路径）
        if (path.toString().equals(realPath.toString()) == false) {
            if (recursiveAccessOnly == false) {
                // add access for path itself
                // 添加对路径自己的访问权限
                policy.add(new FilePermission(realPath.toString(), permissions));
            }
            // add access for files underneath
            // 添加对路径下的文件们的访问权限
            policy.add(new FilePermission(realPath.toString() + realPath.getFileSystem().getSeparator() + "-", permissions));
        }
    }
}
