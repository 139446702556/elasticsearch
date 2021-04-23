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

import org.apache.lucene.util.Constants;
import org.elasticsearch.core.internal.io.IOUtils;
import org.elasticsearch.env.Environment;
import org.elasticsearch.plugins.Platforms;
import org.elasticsearch.plugins.PluginInfo;
import org.elasticsearch.plugins.PluginsService;

import java.io.Closeable;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Spawns native module controller processes if present. Will only work prior to a system call filter being installed.
 */
final class Spawner implements Closeable {

    /*
     * References to the processes that have been spawned, so that we can destroy them.
     * 存储已经创建的进程的引用，以便我们日后可以销毁它
     */
    private final List<Process> processes = new ArrayList<>();
    //标识本地控制器是否已经生成
    private AtomicBoolean spawned = new AtomicBoolean();

    @Override
    public void close() throws IOException {
        IOUtils.close(() -> processes.stream().map(s -> (Closeable) s::destroy).iterator());
    }

    /**
     * Spawns the native controllers for each module.
     * 未每个模块生成本地控制器
     *
     * @param environment The node environment 节点环境变量
     * @param inheritIo   Should the stdout and stderr of the spawned process inherit the
     *                    stdout and stderr of the JVM spawning it?
     *                    生成进程的标准输出和标准错误是否应该继承生成它的jvm的标准输出和标准错误
     * @throws IOException if an I/O error occurs reading the module or spawning a native process
     */
    void spawnNativeControllers(final Environment environment, final boolean inheritIo) throws IOException {
        //如果本地控制器已经生成，则抛出异常
        if (!spawned.compareAndSet(false, true)) {
            throw new IllegalStateException("native controllers already spawned");
        }
        //如果设置中指定的模块目录不存在，则抛出异常
        if (!Files.exists(environment.modulesFile())) {
            throw new IllegalStateException("modules directory [" + environment.modulesFile() + "] not found");
        }
        /*
         * For each module, attempt to spawn the controller daemon. Silently ignore any module that doesn't include a controller for the
         * correct platform.
         */
        //为每个模块尝试生成对应的控制器守护进程，忽略掉包含不正确的控制器的模块
        //遍历全部存在的模块
        List<Path> paths = PluginsService.findPluginDirs(environment.modulesFile());
        for (final Path modules : paths) {
            //如果是文件，则抛出异常
            if (modules.toFile().isFile()){
                continue;
            }
            //加载模块中设置的属性配置信息
            final PluginInfo info = PluginInfo.readFromProperties(modules);
            //获取插件的本地控制器路径
            final Path spawnPath = Platforms.nativeControllerPath(modules);
            //如果本地控制器路径对应的不是文件，则跳过
            if (!Files.isRegularFile(spawnPath)) {
                continue;
            }
            //如果设置为没有本地控制器，则直接抛出异常
            if (!info.hasNativeController()) {
                final String message = String.format(
                    Locale.ROOT,
                    "module [%s] does not have permission to fork native controller",
                    modules.getFileName());
                throw new IllegalArgumentException(message);
            }
            //给当前插件模块的本地控制器创建一个对应的进程，并启动
            final Process process = spawnNativeController(spawnPath, environment.tmpFile(), inheritIo);
            //将进程放入processes容器中，后续统一管理
            processes.add(process);
        }
    }

    /**
     * Attempt to spawn the controller daemon for a given module. The spawned process will remain connected to this JVM via its stdin,
     * stdout, and stderr streams, but the references to these streams are not available to code outside this package.
     * 尝试生成给定模块的控制器守护进程，生成的进程将通过stdin、stdout和stderr流保持和jvm的连接，但是对这些流的引用不能应用于该包以外
     */
    private Process spawnNativeController(final Path spawnPath, final Path tmpPath, final boolean inheritIo) throws IOException {
        final String command;
        //根据不同的os生成对应的启动本地控制器命令文件的路径
        if (Constants.WINDOWS) {
            /*
             * We have to get the short path name or starting the process could fail due to max path limitations. The underlying issue here
             * is that starting the process on Windows ultimately involves the use of CreateProcessW. CreateProcessW has a limitation that
             * if its first argument (the application name) is null, then its second argument (the command line for the process to start) is
             * restricted in length to 260 characters (cf. https://msdn.microsoft.com/en-us/library/windows/desktop/ms682425.aspx). Since
             * this is exactly how the JDK starts the process on Windows (cf.
             * http://hg.openjdk.java.net/jdk8/jdk8/jdk/file/687fd7c7986d/src/windows/native/java/lang/ProcessImpl_md.c#l319), this
             * limitation is in force. As such, we use the short name to avoid any such problems.
             */
            command = Natives.getShortPathName(spawnPath.toString());
        } else {
            command = spawnPath.toString();
        }
        //给指定命令创建对应的os进程
        final ProcessBuilder pb = new ProcessBuilder(command);

        // the only environment variable passes on the path to the temporary directory
        // 清除pb进程中的全部环境变量，并将临时文件目录路径设置到当前指定进程的环境变量中
        pb.environment().clear();
        pb.environment().put("TMPDIR", tmpPath.toString());

        // The process _shouldn't_ write any output via its stdout or stderr, but if it does then
        // it will block if nothing is reading that output. To avoid this we can inherit the
        // JVM's stdout and stderr (which are redirected to files in standard installations).
        //如果继承，则设置当前进程的stdout和stderr跳转到jvm的stdout和stderr中（继承）
        if (inheritIo) {
            pb.redirectOutput(ProcessBuilder.Redirect.INHERIT);
            pb.redirectError(ProcessBuilder.Redirect.INHERIT);
        }

        // the output stream of the process object corresponds to the daemon's stdin
        // 启动进程
        return pb.start();
    }

    /**
     * The collection of processes representing spawned native controllers.
     *
     * @return the processes
     */
    List<Process> getProcesses() {
        return Collections.unmodifiableList(processes);
    }

}
